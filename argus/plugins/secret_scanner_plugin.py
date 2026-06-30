import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

# (label, compiled regex, min_len, max_len)
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # AWS Access Key ID
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    # AWS Secret Access Key (40 base64-ish chars, often preceded by secret/aws)
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}(?:secret|key).{0,5}['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    # Google API Key
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    # Slack token (xox[baprs]-...)
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b")),
    # Stripe live secret key
    ("stripe_secret_key", re.compile(r"\b(sk_live_[0-9A-Za-z]{20,99})\b")),
    # Stripe live publishable key
    ("stripe_publishable_key", re.compile(r"\b(pk_live_[0-9A-Za-z]{20,99})\b")),
    # GitHub personal access token (classic)
    ("github_pat", re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b")),
    # GitHub fine-grained PAT
    ("github_fine_pat", re.compile(r"\b(github_pat_[0-9A-Za-z_]{22,255})\b")),
    # GitHub OAuth token
    ("github_oauth", re.compile(r"\b(gho_[0-9A-Za-z]{36})\b")),
    # GitHub refresh token
    ("github_refresh", re.compile(r"\b(ghr_[0-9A-Za-z]{36})\b")),
    # Generic API key assignments
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{32,64})['\"]")),
    # Private key headers
    ("private_key_block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----")),
    # JWT
    ("jwt_token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    # Heroku API key
    ("heroku_api_key", re.compile(r"(?i)heroku.{0,20}[0-9a-f]{32}")),
    # Generic high-entropy password assignment (best-effort)
    ("password_assignment", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,40})['\"]")),
]


def redact(secret: str) -> str:
    """Return first 4 + '…' + last 4 chars."""
    if len(secret) <= 8:
        return secret[:2] + "…" + secret[-2:]
    return secret[:4] + "…" + secret[-4:]


class SecretScannerPlugin(BasePlugin):
    name = "secret_scanner"
    description = "Regex-based secret scanner for AWS, Google, Slack, Stripe, GitHub, generic keys"
    supported_target_types = ["url", "domain"]

    @staticmethod
    def _scan_text(text: str) -> list[dict]:
        findings: list[dict] = []
        lines = text.splitlines()
        for label, pattern in SECRET_PATTERNS:
            for ln_no, line in enumerate(lines, start=1):
                for m in pattern.finditer(line):
                    # Determine which group is the secret
                    secret_val = None
                    for g in m.groups():
                        if g:
                            secret_val = g
                            break
                    if secret_val is None:
                        secret_val = m.group(0)
                    findings.append({
                        "type": label,
                        "value_redacted": redact(secret_val),
                        "line": ln_no,
                    })
        return findings

    async def run(self, target: str) -> PluginResult:
        try:
            from intel.ssrf import is_safe_url
            t = target.strip()
            if not t:
                return PluginResult(plugin_name=self.name, success=False, error="Empty target")

            # If domain, fetch the homepage
            if "://" not in t and "/" not in t:
                # treat as domain — try https first
                urls = [f"https://{t}/", f"http://{t}/"]
            else:
                urls = [t]

            body_text = ""
            fetched_url = None
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                for url in urls:
                    # SSRF guard
                    safe, _ = is_safe_url(url)
                    if not safe:
                        continue
                    try:
                        async with session.get(url, allow_redirects=True, ssl=False) as resp:
                            if resp.status < 500:
                                body_text = await resp.text(errors="ignore")
                                fetched_url = url
                                break
                    except Exception:
                        continue

            if not body_text and fetched_url is None:
                return PluginResult(plugin_name=self.name, success=False, error="Could not fetch target content")

            scanned_bytes = len(body_text)
            findings = self._scan_text(body_text)

            summary = (
                f"Scanned {scanned_bytes} bytes from {fetched_url or target}; "
                f"found {len(findings)} potential secret(s)."
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "scanned_url": fetched_url,
                    "secrets_found": findings,
                    "count": len(findings),
                    "scanned_bytes": scanned_bytes,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
