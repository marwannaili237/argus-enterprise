import asyncio

import aiohttp
import dns.resolver

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class PortScanPlugin(BasePlugin):
    name = "port_scan"
    description = "Port scanning via Shodan InternetDB and HackerTarget Nmap"
    supported_target_types = ["ip", "domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

            # Resolve to IP if domain
            ip_address = host
            is_ip = host.replace(".", "").isdigit()

            if not is_ip:
                try:
                    loop = asyncio.get_event_loop()
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    answers = await loop.run_in_executor(None, resolver.resolve, host, "A")
                    ip_address = str(answers[0])
                except Exception:
                    ip_address = None

            results: dict = {
                "target": target,
                "host": host,
                "ip": ip_address,
                "internetdb": None,
                "nmap": None,
            }

            async def fetch_internetdb():
                if not ip_address:
                    return
                try:
                    url = f"https://internetdb.shodan.io/{ip_address}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                results["internetdb"] = data
                except Exception as e:
                    results["internetdb_error"] = str(e)

            async def fetch_nmap():
                if not host:
                    return
                try:
                    url = f"https://api.hackertarget.com/nmap/?q={host}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=30)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                if not text.startswith("error"):
                                    # Parse open ports from nmap output
                                    open_ports = []
                                    for line in text.splitlines():
                                        if "open" in line.lower() and "/tcp" in line.lower():
                                            port_match = __import__("re").search(r"(\d+)/tcp\s+open", line)
                                            if port_match:
                                                open_ports.append(int(port_match.group(1)))

                                    results["nmap"] = {
                                        "raw_output": text[:5000],
                                        "open_ports": open_ports,
                                        "port_count": len(open_ports),
                                    }
                                else:
                                    results["nmap"] = {"error": text.strip()}
                except Exception as e:
                    results["nmap_error"] = str(e)

            await asyncio.gather(fetch_internetdb(), fetch_nmap())

            # Merge port data
            all_ports: set[int] = set()
            if results.get("internetdb") and results["internetdb"].get("ports"):
                all_ports.update(results["internetdb"]["ports"])
            if results.get("nmap") and results["nmap"].get("open_ports"):
                all_ports.update(results["nmap"]["open_ports"])

            results["all_open_ports"] = sorted(all_ports)
            results["total_open_ports"] = len(all_ports)

            # Common service mapping
            COMMON_PORTS = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
                993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
                3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
                6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
                27017: "MongoDB", 11211: "Memcached",
            }
            services = {}
            for p in sorted(all_ports):
                if p in COMMON_PORTS:
                    services[p] = COMMON_PORTS[p]
            results["known_services"] = services

            # Risk analysis
            risky_ports = {p for p in all_ports if p in {23, 445, 3389, 5900, 6379, 11211, 27017}}
            results["risky_ports"] = sorted(risky_ports)
            results["risk_flags"] = []
            if risky_ports:
                results["risk_flags"].append(f"⚠️ {len(risky_ports)} risky port(s) open: {', '.join(str(p) for p in sorted(risky_ports))}")
            if 3389 in all_ports:
                results["risk_flags"].append("⚠️ RDP exposed to internet")
            if 6379 in all_ports or 27017 in all_ports:
                results["risk_flags"].append("⚠️ Database port exposed")
            if 23 in all_ports:
                results["risk_flags"].append("⚠️ Telnet (unencrypted) exposed")

            if not all_ports:
                return PluginResult(plugin_name=self.name, success=False, error="No open ports found")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))