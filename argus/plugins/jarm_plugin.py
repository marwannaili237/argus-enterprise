import asyncio
import hashlib
import socket
import ssl

from plugins.base import BasePlugin, PluginResult


class JarmPlugin(BasePlugin):
    name = "jarm"
    description = "Simplified JARM-style TLS fingerprint (TLS version + cipher + cert fingerprint)"
    supported_target_types = ["domain", "url", "ip"]

    @staticmethod
    def _parse_target(target: str) -> tuple[str, int]:
        host = target.strip()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/")[0]
        port = 443
        if "@" in host:
            host = host.split("@", 1)[1]
        if ":" in host:
            # Handle IPv6 in brackets
            if host.startswith("["):
                end = host.find("]")
                if end != -1:
                    h = host[1:end]
                    rest = host[end + 1:]
                    if rest.startswith(":"):
                        port = int(rest[1:].split("/")[0])
                    host = h
            else:
                parts = host.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
                    port = int(parts[1])
        return host, port

    @staticmethod
    def _probe(host: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force a broad set of protocols so we can detect the negotiated version
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:
            pass

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                cipher = ssock.cipher()
                cert_dict = ssock.getpeercert()

        cert_fp = hashlib.sha256(cert_bin).hexdigest() if cert_bin else None

        subject = {}
        issuer = {}
        if cert_dict:
            for field in cert_dict.get("subject", ()):
                for k, v in field:
                    subject[k] = v
            for field in cert_dict.get("issuer", ()):
                for k, v in field:
                    issuer[k] = v

        cipher_name = cipher[0] if cipher else "unknown"
        # JARM-style hash: first 30 chars of sha256(tls_version|cipher|cert_fp)
        jarm_input = f"{version}|{cipher_name}|{cert_fp or ''}"
        jarm_hash = hashlib.sha256(jarm_input.encode()).hexdigest()[:62]

        return {
            "tls_version": version,
            "cipher": cipher_name,
            "cert_fingerprint": cert_fp,
            "subject": subject,
            "issuer": issuer,
            "jarm": jarm_hash,
        }

    async def run(self, target: str) -> PluginResult:
        try:
            host, port = self._parse_target(target)
            if not host:
                return PluginResult(plugin_name=self.name, success=False, error="No host parsed from target")

            loop = asyncio.get_event_loop()
            probe = await loop.run_in_executor(None, self._probe, host, port)

            summary = (
                f"TLS fingerprint for {host}:{port} — version={probe['tls_version']}, "
                f"cipher={probe['cipher']}, cert_sha256={probe['cert_fingerprint'][:16] if probe['cert_fingerprint'] else 'none'}…"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "jarm": probe["jarm"],
                    "tls_version": probe["tls_version"],
                    "cipher": probe["cipher"],
                    "cert_fingerprint": probe["cert_fingerprint"],
                    "cert_subject": probe["subject"],
                    "cert_issuer": probe["issuer"],
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
