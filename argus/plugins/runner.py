import asyncio
import re
from datetime import datetime, timezone
from sqlalchemy import select
from database import AsyncSessionLocal
from models import Investigation, Evidence

# Domain / URL / IP plugins
from plugins.whois_plugin import WhoisPlugin
from plugins.dns_plugin import DnsPlugin
from plugins.certs_plugin import CertsPlugin
from plugins.ip_plugin import IpPlugin
from plugins.http_plugin import HttpPlugin
from plugins.shodan_plugin import ShodanPlugin
from plugins.wayback_plugin import WaybackPlugin
from plugins.bgp_plugin import BgpPlugin
from plugins.reputation_plugin import ReputationPlugin
from plugins.subdomain_plugin import SubdomainPlugin
from plugins.passivedns_plugin import PassiveDnsPlugin
from plugins.pastebin_plugin import PastebinPlugin
from plugins.github_osint_plugin import GithubOsintPlugin

# Email plugins
from plugins.email_plugin import EmailPlugin
from plugins.breach_plugin import BreachPlugin
from plugins.social_email_plugin import SocialEmailPlugin
from plugins.email_verify_plugin import EmailVerifyPlugin
from plugins.email_pattern_plugin import EmailPatternPlugin
from plugins.email_breach_timeline_plugin import EmailBreachTimelinePlugin
from plugins.email_identity_plugin import EmailIdentityPlugin
from plugins.email_security_plugin import EmailSecurityPlugin
from plugins.email_age_plugin import EmailAgePlugin
from plugins.email_domain_profile_plugin import EmailDomainProfilePlugin
from plugins.email_username_plugin import EmailUsernamePlugin
from plugins.email_disposable_plugin import EmailDisposablePlugin
from plugins.email_reverse_plugin import EmailReversePlugin

# Username / Phone / Image
from plugins.username_plugin import UsernamePlugin
from plugins.phone_plugin import PhonePlugin
from plugins.image_plugin import ImagePlugin
from plugins.profile_plugin import ProfilePlugin
from plugins.entity_plugin import EntityPlugin

# New OSINT plugins
from plugins.google_dork_plugin import GoogleDorkPlugin
from plugins.github_dork_plugin import GithubDorkPlugin
from plugins.redirect_chain_plugin import RedirectChainPlugin
from plugins.robots_sitemap_plugin import RobotsSitemapPlugin
from plugins.ssl_analysis_plugin import SslAnalysisPlugin
from plugins.mac_lookup_plugin import MacLookupPlugin
from plugins.crypto_tracer_plugin import CryptoTracerPlugin
from plugins.onion_checker_plugin import OnionCheckerPlugin
from plugins.pdf_metadata_plugin import PdfMetadataPlugin
from plugins.dnssec_plugin import DnssecPlugin
from plugins.spf_dmarc_plugin import SpfDmarcPlugin
from plugins.shodan_dork_plugin import ShodanDorkPlugin
from plugins.social_posts_plugin import SocialPostsPlugin
from plugins.port_scan_plugin import PortScanPlugin
from plugins.technology_plugin import TechnologyPlugin

# ─── Monster Mode: 28 new free plugins ────────────────────────────────
# Threat intel
from plugins.threatfox_plugin import ThreatFoxPlugin
from plugins.malwarebazaar_plugin import MalwareBazaarPlugin
from plugins.urlscan_plugin import UrlScanPlugin
from plugins.virustotal_plugin import VirusTotalPlugin
from plugins.greynoise_plugin import GreyNoisePlugin
from plugins.opensanctions_plugin import OpenSanctionsPlugin
from plugins.otx_plugin import OtxPlugin

# Corporate / legal / academic
from plugins.gdelt_plugin import GdeltPlugin
from plugins.opencorporates_plugin import OpenCorporatesPlugin
from plugins.secedgar_plugin import SecEdgarPlugin
from plugins.gleif_plugin import GleifPlugin
from plugins.vies_plugin import ViesPlugin
from plugins.openalex_plugin import OpenAlexPlugin
from plugins.crossref_plugin import CrossrefPlugin

# Security / validation
from plugins.typosquat_plugin import TyposquatPlugin
from plugins.jarm_plugin import JarmPlugin
from plugins.cobaltstrike_plugin import CobaltstrikePlugin
from plugins.secret_scanner_plugin import SecretScannerPlugin
from plugins.iban_plugin import IbanPlugin
from plugins.vin_plugin import VinPlugin
from plugins.flight_plugin import FlightPlugin

# Crypto / web3 / social
from plugins.blockstream_plugin import BlockstreamPlugin
from plugins.etherscan_plugin import EtherscanPlugin
from plugins.mastodon_plugin import MastodonPlugin
from plugins.bluesky_plugin import BlueskyPlugin
from plugins.nostr_plugin import NostrPlugin
from plugins.stackexchange_plugin import StackExchangePlugin
from plugins.ens_resolver_plugin import EnsResolverPlugin

# AI
from plugins.ai_analysis import AiAnalysisPlugin

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
CRYPTO_RE = re.compile(r"^(0x[a-fA-F0-9]{40})$|^(1[a-km-zA-HJ-NP-Z1-9]{25,34})$|^(3[a-km-zA-HJ-NP-Z1-9]{25,34})$|^(bc1[a-zA-HJ-NP-Z0-9]{25,62})$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif"}
USERNAME_RE = re.compile(r"^@?[a-zA-Z0-9_\.]{2,40}$")
# Person name pattern: 2-4 words, each starting with uppercase, may include hyphens/apostrophes
PERSON_RE = re.compile(r"^[A-Z][a-zA-Z\-']{1,30}( [A-Z][a-zA-Z\-']{1,30}){1,3}$")
IMAGE_HOSTS = {
    "imgur.com", "i.imgur.com", "pbs.twimg.com", "cdn.discordapp.com",
    "images.unsplash.com", "upload.wikimedia.org", "i.redd.it",
}
# Monster Mode: new target types
VAT_RE = re.compile(r"^[A-Z]{2}\d{8,12}$")
VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
FLIGHT_RE = re.compile(r"^(?:flight:|callsign:)?([A-Z]{2,3}\d{1,5})$")
HASH_RE = re.compile(r"^(?i:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
NOSTR_RE = re.compile(r"^npub1[023456789acdefghjklmnpqrstuvwxyz]{6,}$")

ALL_PLUGINS = {
    "domain": [
        WhoisPlugin(), DnsPlugin(), CertsPlugin(), IpPlugin(), HttpPlugin(),
        ShodanPlugin(), WaybackPlugin(), BgpPlugin(), ReputationPlugin(),
        SubdomainPlugin(), PassiveDnsPlugin(), PastebinPlugin(), GithubOsintPlugin(),
        GoogleDorkPlugin(), GithubDorkPlugin(), RobotsSitemapPlugin(), SslAnalysisPlugin(),
        DnssecPlugin(), SpfDmarcPlugin(), ShodanDorkPlugin(), PortScanPlugin(), TechnologyPlugin(),
        EmailPatternPlugin(), EmailSecurityPlugin(),
        # Monster Mode additions
        ThreatFoxPlugin(), UrlScanPlugin(), VirusTotalPlugin(), OtxPlugin(),
        TyposquatPlugin(), JarmPlugin(), CobaltstrikePlugin(), SecretScannerPlugin(),
        GdeltPlugin(), SecEdgarPlugin(), GleifPlugin(), OpenAlexPlugin(), CrossrefPlugin(),
        OpenSanctionsPlugin(),
    ],
    "url": [
        WhoisPlugin(), DnsPlugin(), CertsPlugin(), IpPlugin(), HttpPlugin(),
        ShodanPlugin(), WaybackPlugin(), BgpPlugin(), ReputationPlugin(),
        SubdomainPlugin(), PassiveDnsPlugin(), GithubOsintPlugin(),
        GoogleDorkPlugin(), GithubDorkPlugin(), RedirectChainPlugin(), RobotsSitemapPlugin(),
        SslAnalysisPlugin(), DnssecPlugin(), SpfDmarcPlugin(), ShodanDorkPlugin(),
        PdfMetadataPlugin(), PortScanPlugin(), TechnologyPlugin(),
        EmailPatternPlugin(),
        # Monster Mode additions
        ThreatFoxPlugin(), UrlScanPlugin(), VirusTotalPlugin(), OtxPlugin(),
        JarmPlugin(), CobaltstrikePlugin(), SecretScannerPlugin(),
    ],
    "ip": [
        IpPlugin(), DnsPlugin(), ShodanPlugin(), BgpPlugin(),
        ReputationPlugin(), PassiveDnsPlugin(),
        SslAnalysisPlugin(), ShodanDorkPlugin(), PortScanPlugin(),
        # Monster Mode additions
        ThreatFoxPlugin(), VirusTotalPlugin(), GreyNoisePlugin(), OtxPlugin(),
        JarmPlugin(), CobaltstrikePlugin(),
    ],
    "email": [
        EmailPlugin(), BreachPlugin(), SocialEmailPlugin(), GithubOsintPlugin(), PastebinPlugin(),
        GoogleDorkPlugin(), GithubDorkPlugin(), SpfDmarcPlugin(),
        EmailVerifyPlugin(), EmailPatternPlugin(), EmailBreachTimelinePlugin(),
        EmailIdentityPlugin(), EmailSecurityPlugin(), EmailAgePlugin(),
        EmailDomainProfilePlugin(), EmailUsernamePlugin(), EmailDisposablePlugin(),
        EmailReversePlugin(),
        # Monster Mode additions
        ThreatFoxPlugin(), OpenSanctionsPlugin(), GdeltPlugin(),
    ],
    "username": [
        UsernamePlugin(), ProfilePlugin(), GithubOsintPlugin(), PastebinPlugin(),
        GoogleDorkPlugin(), GithubDorkPlugin(), SocialPostsPlugin(),
        # Monster Mode additions
        MastodonPlugin(), BlueskyPlugin(), NostrPlugin(), StackExchangePlugin(),
    ],
    "phone": [PhonePlugin()],
    "image": [ImagePlugin()],
    "person": [
        EntityPlugin(), GithubOsintPlugin(),
        # Monster Mode additions
        OpenSanctionsPlugin(), GdeltPlugin(), SecEdgarPlugin(),
        OpenAlexPlugin(), CrossrefPlugin(), GleifPlugin(),
    ],
    "company": [
        EntityPlugin(), GithubOsintPlugin(),
        # Monster Mode additions
        OpenCorporatesPlugin(), SecEdgarPlugin(), GleifPlugin(), OpenSanctionsPlugin(),
        GdeltPlugin(), OpenAlexPlugin(), CrossrefPlugin(),
    ],
    "mac": [MacLookupPlugin()],
    "crypto": [
        CryptoTracerPlugin(),
        # Monster Mode additions
        BlockstreamPlugin(), EtherscanPlugin(),
    ],
    # Monster Mode: new target types
    "vat": [ViesPlugin()],
    "vin": [VinPlugin()],
    "flight": [FlightPlugin()],
    "iban": [IbanPlugin()],
    "hash": [MalwareBazaarPlugin(), ThreatFoxPlugin()],
    "npub": [NostrPlugin()],
    "ens": [EnsResolverPlugin()],
}
AI_PLUGIN = AiAnalysisPlugin()


def classify_target(target: str) -> str:
    t = target.strip()

    if t.startswith(("http://", "https://")):
        lower = t.lower().split("?")[0]
        if any(lower.endswith(ext) for ext in IMAGE_EXTS):
            return "image"
        host = lower.split("://")[1].split("/")[0]
        if host in IMAGE_HOSTS:
            return "image"
        return "url"

    if IP_RE.match(t):
        return "ip"
    if EMAIL_RE.match(t):
        return "email"

    if CRYPTO_RE.match(t):
        return "crypto"

    if MAC_RE.match(t):
        return "mac"

    if t.startswith("+") and PHONE_RE.match(t):
        return "phone"
    digits_only = re.sub(r"[\s\-\(\)]", "", t)
    if digits_only.isdigit() and 7 <= len(digits_only) <= 15:
        return "phone"

    if t.startswith("@") and USERNAME_RE.match(t):
        # Federated handle (e.g. @user@instance.social)?
        if t.count("@") == 2:
            return "username"
        return "username"

    # Monster Mode: new target types
    if t.endswith(".eth"):
        return "ens"
    if NOSTR_RE.match(t):
        return "npub"
    if VAT_RE.match(t):
        return "vat"
    if IBAN_RE.match(t):
        return "iban"
    if VIN_RE.match(t):
        return "vin"
    if HASH_RE.match(t):
        return "hash"
    m = FLIGHT_RE.match(t)
    if m and (t.lower().startswith("flight:") or t.lower().startswith("callsign:")):
        return "flight"

    if DOMAIN_RE.match(t):
        # ENS names are domains but we route them to ens_resolver too
        return "domain"

    if USERNAME_RE.match(t) and "." not in t:
        return "username"

    # Person/company name detection (2-4 capitalized words)
    if PERSON_RE.match(t):
        return "person"

    return "unknown"


def get_plugins_for_type(target_type: str):
    return ALL_PLUGINS.get(target_type, [])


async def run_investigation(investigation_id: int, template: str | None = None):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
        inv = result.scalar_one_or_none()
        if not inv:
            return

        # Resolve plugins — template or default
        if template:
            try:
                from plugins.templates import get_template_plugins
                plugins = get_template_plugins(template, inv.target_type)
            except KeyError:
                plugins = get_plugins_for_type(inv.target_type)
        else:
            plugins = get_plugins_for_type(inv.target_type)

        total = len(plugins)

        if not plugins:
            inv.status = "completed"
            inv.summary = (
                f"⚠️ No plugins available for target type: `{inv.target_type}`\n\n"
                "Supported: domain · URL · IP · email · @username · phone · image · person/company name"
            )
            inv.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await db.commit()
            await _notify_telegram(inv, [], ai_report=None)
            return

        # Update Telegram with initial progress
        await _update_telegram_progress(inv, 0, total, plugins[0].name if plugins else "")

        # ─── Concurrent (semaphore-bounded) plugin runner ────────────────
        # Low-end friendly: cap parallelism at 5 by default, configurable via env.
        from config import get_settings as _get_settings
        _settings = _get_settings()
        max_concurrency = getattr(_settings, "max_concurrent_plugins", 5)
        sem = asyncio.Semaphore(max_concurrency)
        progress_counter = {"done": 0}
        progress_lock = asyncio.Lock()

        async def _run_one(plugin):
            """Run a single plugin with cache/timeout/retry/semaphore."""
            async with sem:
                try:
                    from plugins.timeout import run_with_timeout
                    from plugins.retry import run_with_retry
                    from cache import cache_get, cache_set
                    from api.routes.metrics import increment_plugin_exec
                    from plugins.base import PluginResult

                    cache_key = f"{plugin.name}:{inv.target}"
                    cached = cache_get(cache_key)
                    if cached is not None:
                        r = PluginResult(
                            plugin_name=plugin.name,
                            success=cached.get("success", False),
                            data=cached.get("data", {}),
                            error=cached.get("error"),
                        )
                    else:
                        per_plugin_timeout = max(_settings.investigation_timeout_seconds / max(total, 1), 10)
                        r = await asyncio.wait_for(
                            run_with_retry(plugin, inv.target, max_retries=1),
                            timeout=per_plugin_timeout,
                        )
                        cache_set(cache_key, {
                            "success": r.success,
                            "data": r.data,
                            "error": r.error,
                        })

                    increment_plugin_exec(plugin.name)
                    return r
                except asyncio.TimeoutError:
                    from plugins.base import PluginResult
                    from api.routes.metrics import increment_plugin_exec
                    increment_plugin_exec(plugin.name)
                    return PluginResult(plugin_name=plugin.name, success=False, error="Plugin timed out")
                except Exception as exc:
                    from plugins.base import PluginResult
                    return PluginResult(plugin_name=plugin.name, success=False, error=str(exc))

        async def _run_and_track(plugin):
            r = await _run_one(plugin)
            async with progress_lock:
                progress_counter["done"] += 1
                done = progress_counter["done"]
            # Persist evidence as it completes (so partial results survive crash)
            evidence = Evidence(
                investigation_id=inv.id,
                plugin_name=r.plugin_name,
                data=r.data if r.success else {"error": r.error},
            )
            db.add(evidence)
            await db.flush()
            await _update_telegram_progress(inv, done, total, r.plugin_name)
            return r

        # Run all plugins concurrently
        results = await asyncio.gather(*[_run_and_track(p) for p in plugins], return_exceptions=True)
        evidence_list = []
        combined_data = {}
        for r in results:
            if isinstance(r, Exception):
                continue
            evidence_list.append(r)
            if r.success:
                combined_data[r.plugin_name] = r.data

        # ─── Post-investigation: entity extraction + IOC enrichment ──────
        try:
            from intel.entity_extractor import extract_entities
            from intel.plugin_deps import yield_follow_ups
            from models import EnrichedEntity
            # Static regex extraction
            entities = extract_entities(inv.target, inv.target_type, combined_data)
            # Dynamic follow-ups from plugin outputs (subdomain→IP, dns→IP, etc.)
            seen_keys = {(e["type"], e["value"].lower()) for e in entities}
            for plugin_name, plugin_data in combined_data.items():
                for follow_target, follow_type, source in yield_follow_ups(plugin_name, plugin_data, inv.target):
                    key = (follow_type, follow_target.lower())
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    entities.append({
                        "type": follow_type,
                        "value": follow_target,
                        "source": source,
                        "context": f"Follow-up from {source}",
                        "confidence": 70,
                    })
            for ent in entities:
                db.add(EnrichedEntity(
                    investigation_id=inv.id,
                    entity_type=ent["type"],
                    value=ent["value"],
                    source_plugin=ent.get("source", "regex"),
                    context=ent.get("context", "")[:500],
                    confidence=ent.get("confidence", 80),
                ))
        except Exception:
            pass

        # ─── Chain of custody: hash the combined evidence ────────────────
        try:
            import hashlib
            import json as _json
            from models import ChainOfCustody
            sha = hashlib.sha256(_json.dumps(combined_data, default=str, sort_keys=True).encode()).hexdigest()
            db.add(ChainOfCustody(
                investigation_id=inv.id,
                action="collected",
                actor=str(inv.user_id),
                sha256=sha,
                details={"plugin_count": len(combined_data), "target": inv.target},
            ))
        except Exception:
            pass

        ai_report = None
        # AI Analysis: respect mode setting to control token usage
        if combined_data and settings.ai_analysis_mode != "disabled":
            ai_result = None
            
            # Try Ollama first if mode is "ollama" or "auto"
            if settings.ai_analysis_mode in ("ollama", "auto"):
                from intel.ollama_client import maybe_generate_report
                ollama_result = await maybe_generate_report(inv.target, combined_data)
                if ollama_result:
                    from plugins.base import PluginResult
                    ai_result = PluginResult(
                        plugin_name="ai_analysis",
                        success=True,
                        data={"report": ollama_result.get("report"), "model": ollama_result.get("model"), "engine": "ollama"},
                    )
            
            # Fall back to Gemini if mode is "gemini" or "auto" (and Ollama didn't work)
            if not ai_result and settings.ai_analysis_mode in ("gemini", "auto") and AI_PLUGIN._configured:
                ai_result = await AI_PLUGIN.run(inv.target, evidence_data=combined_data)
            
            if ai_result and ai_result.success:
                ai_report = ai_result.data.get("report")
                db.add(Evidence(
                    investigation_id=inv.id,
                    plugin_name="ai_analysis",
                    data=ai_result.data,
                ))

        inv.status = "completed"
        raw_summary = _build_summary(inv.target, inv.target_type, evidence_list)
        inv.summary = _append_threat_level(raw_summary, evidence_list)
        inv.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()

        await _notify_telegram(inv, evidence_list, ai_report=ai_report)


def _trunc(s, n=80):
    s = str(s)
    return s[:n] + "…" if len(s) > n else s


# ─── Task 6: Progress Reporting ─────────────────────────────────────────

def _progress_summary(completed: int, total: int, current_plugin: str) -> str:
    """Build a progress string like 'Running plugin 3/13: dns…'"""
    pct = int((completed / total) * 100) if total else 0
    bar_len = 10
    filled = int(bar_len * completed / total) if total else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    return f"⏳ Running plugin {completed}/{total}: {current_plugin}… [{bar}] {pct}%"


async def _update_telegram_progress(inv: Investigation, completed: int, total: int, current_plugin: str):
    """Edit the initial Telegram message to show real-time progress."""
    if not inv.telegram_chat_id or not inv.telegram_message_id:
        return
    try:
        from config import get_settings
        import aiohttp
        import json as _json

        settings = get_settings()
        if not settings.telegram_bot_token:
            return

        text = _progress_summary(completed, total, current_plugin)
        text += f"\n\n_This message auto-updates._"

        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/editMessageText"
        payload = {
            "chat_id": inv.telegram_chat_id,
            "message_id": inv.telegram_message_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=payload)
    except Exception:
        pass


# ─── Task 8: Threat Level Emoji ─────────────────────────────────────────

def _compute_threat_level(evidence_list) -> tuple[str, str]:
    """
    Analyze evidence and compute a threat level.
    Returns (level, emoji_str) e.g. ("HIGH", "🔴 HIGH")
    """
    score = 0  # 0=LOW, 1-2=MEDIUM, 3-4=HIGH, 5+=CRITICAL

    for r in evidence_list:
        if not r.success:
            continue
        d = r.data or {}

        # Threats found (reputation plugin)
        if r.plugin_name == "reputation":
            threats = d.get("threats", [])
            if threats:
                score += min(len(threats), 3)
            if d.get("is_tor_exit"):
                score += 2

        # CVEs (shodan)
        if r.plugin_name == "shodan":
            vulns = d.get("all_vulns", [])
            if vulns:
                score += min(len(vulns), 3)

        # Breach data
        if r.plugin_name == "breach":
            if d.get("breach_found"):
                score += 1
            if d.get("credentials_leaked"):
                score += 2

        # Proxy/VPN
        if r.plugin_name == "ip_geo":
            if d.get("is_proxy"):
                score += 2

        # Disposable email
        if r.plugin_name == "email":
            if d.get("disposable"):
                score += 1
            if d.get("blacklisted"):
                score += 2

    if score >= 5:
        return "CRITICAL", "🔴 CRITICAL"
    elif score >= 3:
        return "HIGH", "🔴 HIGH"
    elif score >= 1:
        return "MEDIUM", "🟡 MEDIUM"
    else:
        return "LOW", "🟢 LOW"


def _build_summary(target: str, target_type: str, results) -> str:
    type_emoji = {
        "domain": "🌐", "url": "🔗", "ip": "🖥️", "email": "📧",
        "username": "👤", "phone": "📞", "image": "🖼️", "unknown": "❓",
        "person": "🧑", "company": "🏢", "mac": "🔌", "crypto": "₿",
    }
    lines = [f"{type_emoji.get(target_type, '🔍')} *Investigation: {target}*", f"Type: `{target_type}`", ""]

    for r in results:
        if not r.success:
            continue
        d = r.data or {}

        # ─── Domain/URL/IP ────────────────────────────────────────────────
        if r.plugin_name == "whois":
            lines.append("📋 *WHOIS*")
            if d.get("registrar"):
                lines.append(f"  Registrar: {d['registrar']}")
            if d.get("creation_date"):
                lines.append(f"  Created: {str(d['creation_date'])[:10]}")
            if d.get("expiration_date"):
                lines.append(f"  Expires: {str(d['expiration_date'])[:10]}")
            if d.get("country"):
                lines.append(f"  Country: {d['country']}")
            if d.get("emails"):
                lines.append(f"  Contacts: {', '.join(list(d['emails'])[:2])}")
            lines.append("")

        elif r.plugin_name == "dns":
            lines.append("🌐 *DNS*")
            rec = d.get("records", {})
            if rec.get("A"):
                lines.append(f"  A: {', '.join(rec['A'][:3])}")
            if rec.get("MX"):
                lines.append(f"  MX: {rec['MX'][0]}")
            if rec.get("NS"):
                lines.append(f"  NS: {', '.join(rec['NS'][:2])}")
            if rec.get("TXT"):
                lines.append(f"  TXT: {rec['TXT'][0][:60]}")
            lines.append("")

        elif r.plugin_name == "certs":
            lines.append("🔐 *Cert Transparency*")
            lines.append(f"  Certs: {d.get('total_certs', 0)}")
            subs = d.get("subdomains", [])
            if subs:
                lines.append(f"  Subdomains: {d.get('total_subdomains', len(subs))}")
                lines.append(f"  Sample: {', '.join(subs[:4])}")
            lines.append("")

        elif r.plugin_name == "ip_geo":
            lines.append("📍 *IP Geolocation*")
            lines.append(f"  IP: {d.get('ip')}")
            if d.get("city"):
                lines.append(f"  {d['city']}, {d.get('region')}, {d.get('country')}")
            if d.get("isp"):
                lines.append(f"  ISP: {d['isp']}")
            if d.get("asn"):
                lines.append(f"  ASN: {d['asn']}")
            flags = []
            if d.get("is_proxy"):
                flags.append("⚠️ Proxy/VPN")
            if d.get("is_hosting"):
                flags.append("🏢 DC/Hosting")
            if flags:
                lines.append(f"  {', '.join(flags)}")
            lines.append("")

        elif r.plugin_name == "http":
            lines.append("🌍 *HTTP*")
            if d.get("title"):
                lines.append(f"  Title: {_trunc(d['title'])}")
            lines.append(f"  Status: {d.get('status_code')}")
            techs = d.get("technologies", [])
            if techs:
                lines.append(f"  Tech: {', '.join(techs[:6])}")
            sec = d.get("security_headers", {})
            if isinstance(sec, dict):
                lines.append(f"  Security headers: {len(sec)} present")
            lines.append("")

        elif r.plugin_name == "shodan":
            ports = d.get("all_open_ports", [])
            vulns = d.get("all_vulns", [])
            tags = d.get("all_tags", [])
            if ports or vulns or tags:
                lines.append("🔌 *Shodan (InternetDB)*")
                if ports:
                    lines.append(f"  Open ports: {', '.join(str(p) for p in ports[:15])}")
                if tags:
                    lines.append(f"  Tags: {', '.join(tags)}")
                if vulns:
                    lines.append(f"  ⚠️ CVEs: {', '.join(vulns[:5])}")
                for flag in d.get("risk_flags", []):
                    lines.append(f"  {flag}")
                lines.append("")

        elif r.plugin_name == "wayback":
            if d.get("has_archive"):
                lines.append("📦 *Wayback Machine*")
                if d.get("first_seen"):
                    lines.append(f"  First seen: {d['first_seen']}")
                if d.get("last_seen"):
                    lines.append(f"  Last seen: {d['last_seen']}")
                if d.get("snapshot_pages"):
                    lines.append(f"  Snapshot pages: {d['snapshot_pages']}")
                if d.get("first_snapshot_url"):
                    lines.append(f"  [Oldest snapshot]({d['first_snapshot_url']})")
                recent = d.get("recent_snapshots", [])
                if recent:
                    lines.append(f"  Recent: {' · '.join(s['date'] for s in recent[:3])}")
                lines.append("")

        elif r.plugin_name == "bgp":
            if d.get("asn"):
                lines.append("🌐 *BGP / ASN*")
                lines.append(f"  ASN: AS{d['asn']} — {d.get('asn_name', '')}")
                if d.get("prefix"):
                    lines.append(f"  Prefix: {d['prefix']}")
                if d.get("country"):
                    lines.append(f"  Country: {d['country']}")
                if d.get("peer_count"):
                    lines.append(f"  Peers: {d['peer_count']}")
                abuse = d.get("abuse_contacts", [])
                if abuse:
                    lines.append(f"  Abuse: {', '.join(abuse[:2])}")
                ixs = d.get("ix_presence", [])
                if ixs:
                    ix_names = [ix.get("name", "") for ix in ixs[:3]]
                    lines.append(f"  IXPs: {', '.join(ix_names)}")
                lines.append("")

        elif r.plugin_name == "reputation":
            threats = d.get("threats", [])
            if threats:
                lines.append("🚨 *Threat Intelligence*")
                for t in threats[:6]:
                    lines.append(f"  {t}")
                lines.append("")
            elif d.get("threat_count") == 0:
                lines.append("🟢 *Threat Intel*: No threats detected\n")

        elif r.plugin_name == "subdomains":
            total = d.get("total_found", 0)
            if total:
                lines.append("🔎 *Subdomain Enumeration*")
                lines.append(f"  Found: {total} subdomains")
                subs = d.get("subdomains", [])
                if subs:
                    lines.append(f"  Sample: {', '.join(subs[:8])}")
                confirmed = d.get("brute_force_confirmed", [])
                if confirmed:
                    lines.append(f"  DNS-confirmed: {len(confirmed)}")
                lines.append("")

        elif r.plugin_name == "passive_dns":
            rev = d.get("reverse_ip_domains", [])
            hist = d.get("ip_history", [])
            nmap = d.get("nmap_scan")
            if rev or hist or nmap:
                lines.append("📡 *Passive DNS / Reverse IP*")
                if rev:
                    lines.append(f"  Shared hosting: {d.get('shared_hosting_count', len(rev))} domains")
                    lines.append(f"  Sample: {', '.join(rev[:4])}")
                if hist:
                    lines.append(f"  IP history:")
                    for h in hist[:3]:
                        lines.append(f"    {h.get('ip')} ({h.get('location')}) — {h.get('date')}")
                if nmap:
                    # Extract just open ports line
                    for line in nmap.splitlines():
                        if "open" in line.lower():
                            lines.append(f"  Nmap: {line.strip()[:80]}")
                lines.append("")

        elif r.plugin_name == "pastes":
            exposure = d.get("exposure_score", 0)
            gh = d.get("github_code_results", 0)
            pb = len(d.get("pastebin_urls", []))
            ps = len(d.get("psbdmp_pastes", []))
            intelx = d.get("intelx", {})
            if exposure or gh or pb or ps:
                lines.append("📋 *Paste / Leak Exposure*")
                if gh:
                    lines.append(f"  GitHub code mentions: {gh}")
                    sample = d.get("github_code_sample", [])
                    for s in sample[:2]:
                        lines.append(f"    [{s.get('repo')}]({s.get('url')})")
                if pb:
                    lines.append(f"  Pastebin hits: {pb}")
                    for url in d.get("pastebin_urls", [])[:3]:
                        lines.append(f"    {url}")
                if ps:
                    lines.append(f"  PSBDMP hits: {ps}")
                if intelx and intelx.get("total"):
                    lines.append(f"  IntelX: {intelx['total']} records")
                lines.append("")

        elif r.plugin_name == "github_osint":
            total = d.get("total_github_exposure", 0)
            if total:
                lines.append("🐙 *GitHub OSINT*")
                code = d.get("code_mentions", {})
                commits = d.get("commits", {})
                repos = d.get("repos", {})
                users = d.get("users", {})
                if code.get("total"):
                    lines.append(f"  Code mentions: {code['total']}")
                    for item in code.get("items", [])[:2]:
                        lines.append(f"    [{item.get('repo')}]({item.get('url')})")
                if commits.get("total"):
                    lines.append(f"  Commit mentions: {commits['total']}")
                if repos.get("total"):
                    lines.append(f"  Repo mentions: {repos['total']}")
                if users.get("total"):
                    lines.append(f"  Users found: {users['total']}")
                    for u in users.get("items", [])[:2]:
                        lines.append(f"    [{u['login']}]({u['url']})")
                lines.append("")

        # ─── New OSINT plugins ────────────────────────────────────────
        if r.plugin_name == "google_dorks":
            total = d.get("total_findings", 0)
            if total:
                lines.append("🔍 *Google Dorks*")
                lines.append(f"  Findings: {total}")
                by_dork = d.get("dorks", {})
                for dork, urls in by_dork.items():
                    if urls:
                        lines.append(f"  {dork}: {len(urls)} result(s)")
                lines.append("")

        elif r.plugin_name == "github_dorks":
            total = d.get("total_findings", 0)
            if total:
                lines.append("🐙 *GitHub Dorks*")
                lines.append(f"  Findings: {total}")
                for item in d.get("findings", [])[:5]:
                    lines.append(f"  [{item.get('repo')}]({item.get('url')})")
                lines.append("")
            elif d.get("queries"):
                any_hits = any(v.get("total", 0) > 0 for v in d["queries"].values())
                if any_hits:
                    lines.append("🐙 *GitHub Dorks*")
                    for q, v in d["queries"].items():
                        if v.get("total", 0) > 0:
                            lines.append(f"  {q}: {v['total']} hits")
                    lines.append("")

        elif r.plugin_name == "redirect_chain":
            hops = d.get("total_hops", 0)
            if hops > 1:
                lines.append("↪️ *Redirect Chain*")
                lines.append(f"  Hops: {hops}")
                if d.get("has_loop"):
                    lines.append("  ⚠️ Redirect loop detected!")
                trackers = d.get("tracker_intermediaries", [])
                if trackers:
                    lines.append(f"  📊 Tracker intermediaries: {len(trackers)}")
                chain = d.get("chain", [])
                for hop in chain[:8]:
                    lines.append(f"  {hop.get('status')} → {_trunc(hop.get('url', ''), 50)}")
                lines.append("")

        elif r.plugin_name == "robots_sitemap":
            rt = d.get("robots_txt")
            sm = d.get("sitemap")
            lines.append("🤖 *Robots.txt / Sitemap*")
            if rt and rt.get("found"):
                lines.append(f"  Robots.txt: {rt.get('disallow_count', 0)} Disallow, {rt.get('allow_count', 0)} Allow")
                sensitive = rt.get("sensitive_paths", [])
                if sensitive:
                    lines.append(f"  ⚠️ Sensitive paths: {', '.join(sensitive[:5])}")
            else:
                lines.append("  Robots.txt: ❌ not found")
            if sm and sm.get("found"):
                lines.append(f"  Sitemap.xml: {sm.get('url_count', 0)} URLs")
            else:
                lines.append("  Sitemap.xml: ❌ not found")
            lines.append("")

        elif r.plugin_name == "ssl_analysis":
            lines.append("🔐 *SSL/TLS Analysis*")
            issuer = d.get("issuer", {})
            lines.append(f"  Issuer: {issuer.get('Organization', 'Unknown')}")
            lines.append(f"  Algorithm: {d.get('signature_algorithm', 'Unknown')}")
            days = d.get("days_remaining")
            if days is not None:
                if d.get("is_expired"):
                    lines.append(f"  ⚠️ EXPIRED {abs(days)} days ago")
                elif d.get("is_expiring_soon"):
                    lines.append(f"  ⚠️ Expires in {days} days")
                else:
                    lines.append(f"  Expires in {days} days")
            hsts = d.get("hsts")
            if hsts:
                lines.append(f"  HSTS: {'✅' if hsts.get('enabled') else '❌'}")
            lines.append("")

        elif r.plugin_name == "mac_lookup":
            lines.append("🔌 *MAC Address Lookup*")
            lines.append(f"  MAC: {d.get('mac')}")
            lines.append(f"  OUI: {d.get('oui')}")
            lines.append(f"  Vendor: {d.get('vendor', 'Unknown')}")
            lines.append(f"  Type: {d.get('type', 'Unknown')}")
            if d.get("is_virtual"):
                lines.append("  🖥️ Virtual MAC address")
            if d.get("is_random"):
                lines.append("  🎲 Locally administered / random")
            lines.append("")

        elif r.plugin_name == "crypto_tracer":
            lines.append("₿ *Crypto Tracer*")
            lines.append(f"  Currency: {d.get('currency')}")
            if d.get("currency") == "BTC":
                bal = d.get("balance_btc") or d.get("final_balance_btc", 0)
                lines.append(f"  Balance: {bal:.8f} BTC")
            elif d.get("currency") == "ETH":
                bal = d.get("balance_eth")
                if bal is not None:
                    lines.append(f"  Balance: {bal:.8f} ETH")
            lines.append(f"  Transactions: {d.get('total_transactions', 0)}")
            lines.append("")

        elif r.plugin_name == "onion_checker":
            lines.append("🧅 *Onion Checker*")
            lines.append(f"  Onion domain: {d.get('onion_domain')}")
            lines.append(f"  Exists: {'✅' if d.get('onion_exists') else '❌'}")
            lines.append(f"  Indexed: {'✅' if d.get('is_indexed') else '❌'}")
            lines.append("")

        elif r.plugin_name == "pdf_metadata":
            meta = d.get("metadata", {})
            if meta:
                lines.append("📄 *PDF Metadata*")
                lines.append(f"  Version: {d.get('pdf_version', 'Unknown')}")
                for key in ["Author", "Creator", "Producer", "CreationDate", "ModDate"]:
                    if key in meta:
                        lines.append(f"  {key}: {_trunc(meta[key], 50)}")
                lines.append("")

        elif r.plugin_name == "dnssec":
            lines.append("🔒 *DNSSEC*")
            lines.append(f"  Enabled: {'✅' if d.get('dnssec_enabled') else '❌'}")
            lines.append(f"  Validated: {'✅' if d.get('validated') else '❌'}")
            if d.get("has_dnskey"):
                lines.append(f"  DNSKEY records: {d.get('dnskey_count', 0)}")
            if d.get("has_ds"):
                lines.append(f"  DS records: {d.get('ds_count', 0)}")
            lines.append("")

        elif r.plugin_name == "spf_dmarc":
            lines.append("📧 *Email Security (SPF/DMARC/DKIM)*")
            spf = d.get("spf")
            dmarc = d.get("dmarc")
            dkim = d.get("dkim")
            if spf and spf.get("found"):
                lines.append(f"  SPF: ✅ {spf.get('all_mechanism', 'N/A')}")
            else:
                lines.append(f"  SPF: ❌")
            if dmarc and dmarc.get("found"):
                lines.append(f"  DMARC: ✅ p={dmarc.get('policy', 'none')}")
            else:
                lines.append(f"  DMARC: ❌")
            if dkim and not dkim.get("found"):
                lines.append(f"  DKIM: ❌")
            elif dkim and dkim.get("found"):
                lines.append(f"  DKIM: ✅")
            lines.append(f"  Grade: {d.get('grade', 'N/A')} ({d.get('score', 0)}/{d.get('max_score', 8)})")
            for flag in d.get("issues", []):
                lines.append(f"  {flag}")
            lines.append("")

        elif r.plugin_name == "shodan_dork":
            idb = d.get("internetdb")
            ht = d.get("hackertarget")
            lines.append("📡 *Shodan Search*")
            if idb:
                ports = idb.get("ports", [])
                vulns = idb.get("vulns", [])
                if ports:
                    lines.append(f"  InternetDB ports: {', '.join(str(p) for p in ports[:10])}")
                if vulns:
                    lines.append(f"  CVEs: {', '.join(vulns[:5])}")
            if ht and not ht.get("error"):
                lines.append(f"  HackerTarget results: {ht.get('result_count', 0)}")
            lines.append("")

        elif r.plugin_name == "social_posts":
            platforms = d.get("platforms_found", [])
            if platforms:
                lines.append("📝 *Social Posts*")
                lines.append(f"  Platforms: {', '.join(platforms)}")
                lines.append(f"  Total posts/events: {d.get('total_posts', 0)}")
                lines.append("")

        elif r.plugin_name == "port_scan":
            ports = d.get("all_open_ports", [])
            if ports:
                lines.append("🔌 *Port Scan*")
                lines.append(f"  Open ports: {d.get('total_open_ports', 0)}")
                lines.append(f"  Ports: {', '.join(str(p) for p in ports[:20])}")
                services = d.get("known_services", {})
                if services:
                    lines.append(f"  Services: {', '.join(f'{p}/{s}' for p, s in list(services.items())[:10])}")
                for flag in d.get("risk_flags", []):
                    lines.append(f"  {flag}")
                lines.append("")

        elif r.plugin_name == "technology":
            techs = d.get("technologies", [])
            if techs:
                lines.append("⚙️ *Technology Detection*")
                lines.append(f"  Detected: {', '.join(techs[:12])}")
                cats = d.get("categories", {})
                for cat, items in cats.items():
                    if items:
                        lines.append(f"  {cat}: {', '.join(items)}")
                lines.append("")

        # ─── Email plugins ────────────────────────────────────────────────
        elif r.plugin_name == "email":
            lines.append("📧 *Email Intel*")
            lines.append(f"  Domain MX: {'✅' if d.get('domain_has_mx') else '❌'}")
            lines.append(f"  Gravatar: {'✅' if d.get('gravatar') else '❌'}")
            rep = d.get("reputation", "unknown")
            lines.append(f"  Reputation: {rep}")
            if d.get("disposable"):
                lines.append(f"  🗑️ Disposable email")
            if d.get("free_provider"):
                lines.append(f"  Free provider")
            profiles = d.get("profiles", [])
            if profiles:
                lines.append(f"  Profiles: {', '.join(profiles[:5])}")
            gh = d.get("github_users", [])
            if gh:
                lines.append(f"  GitHub: [{gh[0]['login']}]({gh[0]['url']})")
            for flag in d.get("risk_flags", []):
                lines.append(f"  {flag}")
            lines.append("")

        elif r.plugin_name == "breach":
            lines.append("🔓 *Breach Check*")
            found = d.get("breach_found", False)
            lines.append(f"  {'🚨 FOUND IN BREACHES' if found else '✅ Not found'}")
            lines.append(f"  Risk: {d.get('risk_level', 'Unknown')}")
            if d.get("credentials_leaked"):
                lines.append("  ⚠️ Credentials/passwords leaked!")
            sources = d.get("breach_sources", [])
            if sources:
                lines.append(f"  Sources: {', '.join(str(s) for s in sources[:5])}")
            lines.append("")

        elif r.plugin_name == "social_email":
            found_list = d.get("registered_on", [])
            count = d.get("registered_count", 0)
            checked = d.get("sites_checked", 0)
            lines.append("🔗 *Email → Social Accounts*")
            lines.append(f"  Checked: {checked} sites | Found: {count}")
            for item in found_list[:8]:
                lines.append(f"  ✓ {item['site']}")
            lines.append("")

        elif r.plugin_name == "email_verify":
            lines.append("✉️ *SMTP Verification*")
            exists = d.get("exists")
            if exists is True:
                lines.append(f"  ✅ Mailbox EXISTS")
            elif exists is False:
                lines.append(f"  ❌ Mailbox does NOT exist")
            else:
                lines.append(f"  ❓ Could not verify ({d.get('status', 'unknown')})")
            if d.get("verified_with"):
                lines.append(f"  Verified via: {d['verified_with']}")
            lines.append("")

        elif r.plugin_name == "email_patterns":
            total = d.get("total_emails", 0)
            lines.append("🔍 *Email Pattern Discovery*")
            lines.append(f"  Domain: {d.get('domain', '')}")
            lines.append(f"  Emails found: {total}")
            if d.get("duckduckgo_emails"):
                lines.append(f"  DuckDuckGo: {len(d['duckduckgo_emails'])} emails")
                for e in d['duckduckgo_emails'][:3]:
                    lines.append(f"    {e}")
            gh_users = d.get("github_users", [])
            if gh_users:
                lines.append(f"  GitHub users: {len(gh_users)}")
            grav = d.get("gravatar_profiles", [])
            if grav:
                lines.append(f"  Gravatar: {len(grav)} profiles")
            lines.append("")

        elif r.plugin_name == "breach_timeline":
            total = d.get("total_breaches", 0)
            severity = d.get("overall_severity", "none")
            lines.append("📅 *Breach Timeline*")
            lines.append(f"  Breaches: {total} | Severity: {severity.upper()}")
            data_types = d.get("data_types_exposed", [])
            if data_types:
                lines.append(f"  Data exposed: {', '.join(data_types[:5])}")
            breaches = d.get("breaches", [])
            for b in breaches[:5]:
                date_str = f" ({b.get('date')})" if b.get('date') else ""
                lines.append(f"    • {b.get('breach_name', '?')}{date_str} [{b.get('severity', '?')}]")
            for flag in d.get("risk_flags", []):
                lines.append(f"  {flag}")
            lines.append("")

        elif r.plugin_name == "email_identity":
            count = d.get("identity_count", 0)
            lines.append("🧑 *Email Identity*")
            lines.append(f"  Identities found: {count}")
            gh_code = d.get("github_code_total", 0)
            if gh_code:
                lines.append(f"  GitHub code: {gh_code} mentions")
            gh_users = d.get("github_users", [])
            if gh_users:
                for u in gh_users[:2]:
                    lines.append(f"  GitHub: [{u['login']}]({u['url']})")
            li = d.get("linkedin_profiles", [])
            if li:
                lines.append(f"  LinkedIn: {len(li)} potential profile(s)")
            patterns = d.get("username_patterns", [])
            if patterns:
                names = [p['username'] for p in patterns[:4]]
                lines.append(f"  Username patterns: {', '.join(names)}")
            lines.append("")

        elif r.plugin_name == "email_security":
            score = d.get("security_score", 0)
            grade = d.get("grade", "?")
            lines.append("🔒 *Email Security*")
            lines.append(f"  Domain: {d.get('domain', '')}")
            lines.append(f"  Score: {score}/100 (Grade {grade})")
            spf = d.get("spf")
            if spf:
                status = "✅" if spf.get("found") else "❌"
                lines.append(f"  SPF: {status}")
            dmarc = d.get("dmarc")
            if dmarc:
                status = "✅" if dmarc.get("found") else "❌"
                policy = dmarc.get("policy", "")
                lines.append(f"  DMARC: {status} {f'(p={policy})' if policy else ''}")
            dkim = d.get("dkim")
            if dkim:
                status = "✅" if dkim.get("found") else "❌"
                sels = dkim.get("selectors_found", [])
                sel_str = f" ({', '.join(sels)})" if sels else ""
                lines.append(f"  DKIM: {status}{sel_str}")
            mx = d.get("mx")
            if mx and mx.get("provider"):
                lines.append(f"  Provider: {mx['provider']}")
            for flag in d.get("risk_flags", [])[:4]:
                lines.append(f"  {flag}")
            lines.append("")

        elif r.plugin_name == "email_age":
            lines.append("📅 *Email Age*")
            earliest = d.get("earliest_known_date")
            source = d.get("earliest_known_source")
            if earliest:
                lines.append(f"  Earliest known: {earliest}")
                lines.append(f"  Source: {source}")
            else:
                lines.append(f"  ❓ Could not estimate age")
            if d.get("github_created_at"):
                lines.append(f"  GitHub account: {d['github_user']} (created {d['github_created_at'][:10]})")
            if d.get("gravatar_profile"):
                lines.append(f"  Gravatar: profile exists")
            if d.get("days_since_domain_creation"):
                lines.append(f"  Domain age: ~{d['days_since_domain_creation']} days")
            lines.append("")

        elif r.plugin_name == "email_domain_profile":
            lines.append("🌐 *Email Domain Profile*")
            lines.append(f"  Domain: {d.get('domain', '')}")
            if d.get("is_free_provider"):
                lines.append(f"  Provider: {d.get('provider_name', 'Free')}")
            else:
                lines.append(f"  Provider: {d.get('provider_name', 'Unknown')}")
            reg = d.get("registration", {})
            if reg.get("creation_date"):
                lines.append(f"  Registered: {str(reg['creation_date'])[:10]}")
            if reg.get("registrar"):
                lines.append(f"  Registrar: {reg['registrar']}")
            if reg.get("nameservers"):
                lines.append(f"  NS: {', '.join(reg['nameservers'][:2])}")
            mx = d.get("mx")
            if mx and mx.get("records"):
                lines.append(f"  MX: {mx['records'][0].get('exchange', '') if isinstance(mx['records'], list) else mx['records'][0]}")
            lines.append("")

        elif r.plugin_name == "email_username":
            found = d.get("found_usernames", [])
            total = d.get("total_variations", 0)
            lines.append("👤 *Email → Username*")
            lines.append(f"  Variations: {total} | Found: {d.get('found_count', 0)}")
            for f in found[:5]:
                name = f.get("name", "")
                repos = f.get("public_repos", 0)
                detail = f" — {name}" if name else ""
                lines.append(f"  ✓ [{f['username']}]({f['url']}){detail} ({repos} repos)")
            lines.append("")

        elif r.plugin_name == "email_disposable":
            is_disp = d.get("disposable", False)
            conf = d.get("confidence", "")
            lines.append("🗑️ *Disposable Check*")
            if is_disp:
                lines.append(f"  🚨 DISPOSABLE ({conf} confidence)")
                if d.get("in_disposable_list"):
                    lines.append(f"  Domain: {d.get('domain', '')} in blocklist ({d.get('list_size', 0)} domains)")
            else:
                lines.append(f"  ✅ Not disposable")
            if d.get("domain_age_days"):
                lines.append(f"  Domain age: {d['domain_age_days']} days")
            for flag in d.get("risk_flags", []):
                lines.append(f"  {flag}")
            lines.append("")

        elif r.plugin_name == "email_reverse":
            total = d.get("total_occurrences", 0)
            by_source = d.get("by_source", {})
            lines.append("🔎 *Email Reverse Search*")
            lines.append(f"  Total occurrences: {total}")
            if by_source:
                source_strs = [f"{k}: {v}" for k, v in by_source.items()]
                lines.append(f"  Sources: {', '.join(source_strs)}")
            occs = d.get("occurrences", [])
            for o in occs[:5]:
                src = o.get("source", "")
                url = o.get("url", o.get("snippet", ""))
                lines.append(f"    [{src}] {_trunc(url, 70)}")
            for flag in d.get("risk_flags", []):
                lines.append(f"  {flag}")
            lines.append("")

        # ─── Username ─────────────────────────────────────────────────────
        elif r.plugin_name == "username":
            lines.append("👤 *Username Hunt*")
            lines.append(f"  Checked: {d.get('platforms_checked', 0)} platforms")
            lines.append(f"  Found: {d.get('found_count', 0)} profiles")
            by_cat = d.get("by_category", {})
            for cat, profiles in by_cat.items():
                if profiles:
                    names = [p["platform"] for p in profiles[:6]]
                    lines.append(f"  {cat}: {', '.join(names)}")
            lines.append("")

        # ─── Phone ───────────────────────────────────────────────────────
        elif r.plugin_name == "phone":
            lines.append("📞 *Phone Intel*")
            lines.append(f"  Number: {d.get('international')}")
            lines.append(f"  Country: {d.get('country')}")
            lines.append(f"  Carrier: {d.get('carrier', 'Unknown')}")
            lines.append(f"  Type: {d.get('line_type', 'Unknown')}")
            if d.get("timezones"):
                lines.append(f"  Timezone: {d['timezones'][0]}")
            lines.append(f"  Valid: {'✅' if d.get('valid') else '⚠️'}")
            for flag in d.get("risk_flags", []):
                lines.append(f"  {flag}")
            lines.append("")

        # ─── Image ────────────────────────────────────────────────────────
        elif r.plugin_name == "image":
            lines.append("🖼️ *Image Forensics*")
            lines.append(f"  Format: {d.get('format')} {d.get('width')}×{d.get('height')}px  {d.get('file_size_kb')} KB")
            lines.append(f"  MD5: `{str(d.get('md5', ''))[:16]}…`")
            if d.get("datetime"):
                lines.append(f"  📅 {d['datetime']}")
            cam = d.get("camera", {})
            if cam:
                lines.append(f"  📷 {cam.get('Make', '')} {cam.get('Model', '')}".strip())
            if d.get("software"):
                lines.append(f"  Software: {d['software']}")
            gps = d.get("gps")
            if gps:
                lines.append(f"  📍 GPS: {gps['latitude']}, {gps['longitude']}")
                lines.append(f"  [View on Maps]({gps['maps_url']})")
            else:
                lines.append("  📍 No GPS data")
            rev = d.get("reverse_search_links", {})
            if rev:
                links = " | ".join(f"[{k}]({v})" for k, v in list(rev.items())[:4])
                lines.append(f"  🔍 {links}")
            lines.append("")

        # ─── Profile ────────────────────────────────────────────────────
        elif r.plugin_name == "profile":
            platforms = d.get("platforms_found", [])
            profiles = d.get("profiles", {})
            cross = d.get("cross_platform", {})
            lines.append("🧑‍💻 *Profile Deep Dive*")
            lines.append(f"  Platforms found: {', '.join(platforms)}")
            if profiles.get("github"):
                gh = profiles["github"]
                lines.append(f"  GitHub: [{gh.get('login')}]({gh.get('url')})")
                if gh.get("name"):
                    lines.append(f"    Name: {gh['name']}")
                if gh.get("company"):
                    lines.append(f"    Company: {gh['company']}")
                if gh.get("location"):
                    lines.append(f"    Location: {gh['location']}")
                lines.append(f"    Repos: {gh.get('public_repos', 0)} | Followers: {gh.get('followers', 0)}")
            if profiles.get("reddit"):
                rd = profiles["reddit"]
                lines.append(f"  Reddit: [{rd.get('name')}]({rd.get('url')})")
                lines.append(f"    Karma: {rd.get('karma_post', 0)} post / {rd.get('karma_comment', 0)} comment")
            if profiles.get("hackernews"):
                hn = profiles["hackernews"]
                lines.append(f"  HN: [{hn.get('id')}]({hn.get('url')}) — {hn.get('karma', 0)} karma")
            if profiles.get("twitter"):
                tw = profiles["twitter"]
                lines.append(f"  Twitter/X: {tw.get('name', 'N/A')}")
                if tw.get("bio"):
                    lines.append(f"    Bio: {_trunc(tw['bio'], 60)}")
            if cross.get("emails"):
                lines.append(f"  📧 Emails: {', '.join(cross['emails'][:3])}")
            if cross.get("locations"):
                lines.append(f"  📍 Locations: {', '.join(cross['locations'][:3])}")
            lines.append("")

        # ─── Entity ─────────────────────────────────────────────────────
        elif r.plugin_name == "entity":
            news = d.get("news", [])
            companies = d.get("companies", [])
            web = d.get("web_results", [])
            linkedin = d.get("linkedin_profiles", [])
            github = d.get("github_users", {})
            lines.append("🔍 *Entity Intelligence*")
            if news:
                lines.append(f"  📰 News ({len(news)} articles)")
                for n in news[:3]:
                    lines.append(f"    • {_trunc(n.get('title', ''), 50)}")
            if companies:
                lines.append(f"  🏢 Companies ({len(companies)} found)")
                for c in companies[:3]:
                    lines.append(f"    • {c.get('name', '')} ({c.get('jurisdiction', '')})")
            if linkedin:
                lines.append(f"  💼 LinkedIn: {len(linkedin)} profile(s) found")
            if github and github.get("total", 0) > 0:
                lines.append(f"  🐙 GitHub: {github['total']} user(s) found")
            if web:
                lines.append(f"  🌐 Web: {len(web)} results")
            lines.append("")

    return "\n".join(lines)


def _append_threat_level(summary: str, evidence_list) -> str:
    """Append threat level to the end of the summary."""
    level_name, level_emoji = _compute_threat_level(evidence_list)
    return summary + f"Threat Level: {level_emoji}\n"


async def _notify_telegram(inv: Investigation, results, ai_report: str | None = None):
    if not inv.telegram_chat_id or not inv.telegram_message_id:
        return
    try:
        from config import get_settings
        import aiohttp
        import json as _json

        settings = get_settings()
        if not settings.telegram_bot_token:
            return

        text = inv.summary or "Investigation completed."
        text += f"\n\n✅ *Done!* Use the buttons below:"

        if len(text) > 4000:
            text = text[:3997] + "…"

        # Build inline keyboard
        row1 = [
            {"text": "📋 Full Results", "callback_data": f"argus_results_{inv.id}"},
        ]
        if ai_report:
            row1.append({"text": "🤖 AI Report", "callback_data": f"argus_analyze_{inv.id}"})

        row2 = [
            {"text": "🔁 Re-investigate", "callback_data": f"argus_reinvest_{inv.id}"},
            {"text": "📜 History", "callback_data": "argus_history_0"},
        ]

        reply_markup = _json.dumps({"inline_keyboard": [row1, row2]})

        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/editMessageText"
        payload = {
            "chat_id": inv.telegram_chat_id,
            "message_id": inv.telegram_message_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": reply_markup,
        }
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=payload)
    except Exception:
        pass
