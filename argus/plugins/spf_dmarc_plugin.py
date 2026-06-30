import asyncio
import re

import aiohttp
import dns.resolver

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class SpfDmarcPlugin(BasePlugin):
    name = "spf_dmarc"
    description = "Email security posture: SPF, DMARC, and DKIM analysis"
    supported_target_types = ["domain", "url", "email"]

    async def run(self, target: str) -> PluginResult:
        try:
            # Extract domain from email if needed
            if "@" in target and not target.startswith(("http://", "https://")):
                domain = target.split("@")[-1]
            else:
                domain = target.replace("https://", "").replace("http://", "").split("/")[0]

            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            results: dict = {
                "domain": domain,
                "spf": None,
                "dmarc": None,
                "dkim": None,
                "issues": [],
                "score": 0,
            }

            def query_spf():
                try:
                    answers = resolver.resolve(domain, "TXT")
                    for r in answers:
                        txt = str(r)
                        if txt.startswith("v=spf1"):
                            return txt
                except Exception:
                    pass
                return None

            def query_dmarc():
                try:
                    answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                    for r in answers:
                        txt = str(r)
                        if "v=DMARC1" in txt:
                            return txt
                except Exception:
                    pass
                return None

            def query_dkim(selector: str):
                try:
                    answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                    for r in answers:
                        return str(r)
                except Exception:
                    return None

            # SPF analysis
            spf_record = await loop.run_in_executor(None, query_spf)
            if spf_record:
                spf_analysis = self._analyze_spf(spf_record)
                results["spf"] = spf_analysis
                if spf_analysis.get("all_mechanism") == "-all":
                    results["score"] += 3
                elif spf_analysis.get("all_mechanism") == "~all":
                    results["score"] += 2
                elif spf_analysis.get("all_mechanism") == "?all":
                    results["score"] += 1
                else:
                    results["issues"].append("⚠️ SPF has no 'all' mechanism - not restrictive")
                    results["score"] += 0
            else:
                results["spf"] = {"found": False}
                results["issues"].append("❌ No SPF record found")

            # DMARC analysis
            dmarc_record = await loop.run_in_executor(None, query_dmarc)
            if dmarc_record:
                dmarc_analysis = self._analyze_dmarc(dmarc_record)
                results["dmarc"] = dmarc_analysis
                policy = dmarc_analysis.get("policy", "none")
                if policy == "reject":
                    results["score"] += 3
                elif policy == "quarantine":
                    results["score"] += 2
                else:
                    results["issues"].append("⚠️ DMARC policy is 'none' - monitoring only")
                    results["score"] += 1
            else:
                results["dmarc"] = {"found": False}
                results["issues"].append("❌ No DMARC record found")

            # DKIM check with common selectors
            common_selectors = ["selector1", "selector2", "google", "k1", "default", "s1", "mail", "smtp"]
            dkim_tasks = [loop.run_in_executor(None, query_dkim, s) for s in common_selectors]
            dkim_results = await asyncio.gather(*dkim_tasks)
            dkim_found = {}
            for selector, record in zip(common_selectors, dkim_results):
                if record:
                    dkim_found[selector] = {"record": record[:100], "present": True}
            if dkim_found:
                results["dkim"] = dkim_found
                results["score"] += 2
            else:
                results["dkim"] = {"found": False, "selectors_checked": common_selectors}
                results["issues"].append("⚠️ No DKIM record found with common selectors")

            results["max_score"] = 8
            results["grade"] = self._grade(results["score"], results["max_score"])

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))

    def _analyze_spf(self, record: str) -> dict:
        analysis: dict = {"record": record, "found": True}
        all_match = re.search(r"([+~?])?all", record)
        if all_match:
            analysis["all_mechanism"] = all_match.group(0)
        includes = re.findall(r"include:(\S+)", record)
        analysis["includes"] = includes
        analysis["include_count"] = len(includes)
        ip4 = re.findall(r"ip4:(\S+)", record)
        ip6 = re.findall(r"ip6:(\S+)", record)
        analysis["ip4_ranges"] = ip4
        analysis["ip6_ranges"] = ip6
        redirects = re.findall(r"redirect=(\S+)", record)
        analysis["redirects"] = redirects
        return analysis

    def _analyze_dmarc(self, record: str) -> dict:
        analysis: dict = {"record": record, "found": True}
        policy_match = re.search(r"p=(\w+)", record)
        if policy_match:
            analysis["policy"] = policy_match.group(1)
        sp_match = re.search(r"sp=(\w+)", record)
        if sp_match:
            analysis["subdomain_policy"] = sp_match.group(1)
        pct_match = re.search(r"pct=(\d+)", record)
        if pct_match:
            analysis["percentage"] = int(pct_match.group(1))
        rua_match = re.search(r"rua=([^;]+)", record)
        if rua_match:
            analysis["rua"] = rua_match.group(1).strip()
        ruf_match = re.search(r"ruf=([^;]+)", record)
        if ruf_match:
            analysis["ruf"] = ruf_match.group(1).strip()
        return analysis

    def _grade(self, score: int, max_score: int) -> str:
        pct = score / max_score if max_score > 0 else 0
        if pct >= 0.9:
            return "A"
        elif pct >= 0.75:
            return "B"
        elif pct >= 0.5:
            return "C"
        elif pct >= 0.25:
            return "D"
        return "F"