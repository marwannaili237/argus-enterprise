"""
Plugin dependency graph — runs dependent plugins after their dependencies
produce specific outputs.

Example: subdomain plugin produces IPs; ip_geo plugin then runs on each IP.

We keep this lightweight: a function that takes a completed plugin result
and yields (target, target_type, source_plugin) tuples for follow-up runs.
These follow-up runs are stored as EnrichedEntity rows but NOT recursively
investigated (would explode combinatorially). The dashboard graph view
shows them.
"""
from typing import Any, Iterator


def yield_follow_ups(plugin_name: str, plugin_data: dict[str, Any], original_target: str) -> Iterator[tuple[str, str, str]]:
    """
    Given a completed plugin's output, yield (target, target_type, source_plugin)
    tuples for follow-up entity extraction. Used by the runner to populate
    EnrichedEntity rows that didn't exist as direct regex matches.
    """
    if not isinstance(plugin_data, dict):
        return

    # Subdomain plugin → exposes IPs as new IP-type entities
    if plugin_name == "subdomains":
        for sd in (plugin_data.get("subdomains") or [])[:50]:
            if isinstance(sd, dict):
                name = sd.get("name") or sd.get("subdomain")
                ip = sd.get("ip")
                if name and ip:
                    yield (ip, "ip", "subdomains")
            elif isinstance(sd, str):
                # Just a subdomain name — yield as domain entity
                yield (sd, "domain", "subdomains")

    # DNS plugin → exposes A records as IPs
    elif plugin_name == "dns":
        records = plugin_data.get("records", {}) or {}
        for ip in (records.get("A") or [])[:10]:
            yield (ip, "ip", "dns")
        for ip in (records.get("AAAA") or [])[:10]:
            yield (ip, "ip", "dns")
        for ns in (records.get("NS") or [])[:10]:
            yield (ns, "domain", "dns")
        for mx in (records.get("MX") or [])[:10]:
            # MX records look like "10 mail.example.com"
            parts = str(mx).split()
            if len(parts) >= 2:
                yield (parts[1], "domain", "dns")

    # Cert transparency → exposes subdomains
    elif plugin_name == "certs":
        for sd in (plugin_data.get("subdomains") or [])[:50]:
            yield (sd, "domain", "certs")

    # BGP → exposes ASN
    elif plugin_name == "bgp":
        asn = plugin_data.get("asn")
        if asn:
            yield (f"AS{asn}", "asn", "bgp")

    # Email plugin → exposes domain
    elif plugin_name == "email":
        domain = plugin_data.get("domain")
        if domain:
            yield (domain, "domain", "email")

    # WHOIS → exposes name servers, contact emails
    elif plugin_name == "whois":
        for ns in (plugin_data.get("name_servers") or [])[:10]:
            yield (ns, "domain", "whois")
        for email in (plugin_data.get("emails") or [])[:5]:
            yield (email, "email", "whois")

    # Shodan → exposes ports as entities (for graphing)
    elif plugin_name == "shodan":
        for port in (plugin_data.get("all_open_ports") or [])[:20]:
            yield (f"port:{port}", "port", "shodan")
        for cve in (plugin_data.get("all_vulns") or [])[:20]:
            yield (cve, "cve", "shodan")


def detect_dependencies(plugin_results: list[dict]) -> dict[str, list[str]]:
    """
    Build a dependency map: plugin_name -> list of plugin_names whose output
    it consumes. Currently static, but could be made dynamic.
    """
    # Static dependency map (based on data flow, not execution order)
    deps = {
        "ip_geo": ["dns", "subdomains", "passive_dns"],
        "bgp": ["dns", "subdomains"],
        "shodan": ["dns", "subdomains"],
        "reputation": ["dns", "subdomains"],
        "cobaltstrike": ["http"],
        "secret_scanner": ["http"],
        "jarm": ["dns"],
    }
    return deps


def topological_sort(plugins: list) -> list:
    """
    Sort plugins so that dependencies come before dependents.
    Plugins with no dependency info run first (in original order).
    Returns a new list.
    """
    deps = detect_dependencies([])
    plugin_names = [p.name for p in plugins]
    plugin_by_name = {p.name: p for p in plugins}

    # Compute in-degree for each plugin (only counting deps that exist in our set)
    in_degree = {p.name: 0 for p in plugins}
    edges: dict[str, list[str]] = {p.name: [] for p in plugins}
    for dependent, dep_list in deps.items():
        if dependent not in plugin_by_name:
            continue
        for dep in dep_list:
            if dep in plugin_by_name:
                edges[dep].append(dependent)
                in_degree[dependent] += 1

    # Kahn's algorithm
    queue = [p for p in plugins if in_degree[p.name] == 0]
    sorted_list: list = []
    while queue:
        node = queue.pop(0)
        sorted_list.append(node)
        for downstream in edges[node.name]:
            in_degree[downstream] -= 1
            if in_degree[downstream] == 0:
                sorted_list.append(plugin_by_name[downstream])

    # Append any leftover (cycles — shouldn't happen but be defensive)
    for p in plugins:
        if p not in sorted_list:
            sorted_list.append(p)

    return sorted_list
