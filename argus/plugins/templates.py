"""
Predefined investigation templates — each maps target_type to a list of plugin names.

Usage:
    from plugins.templates import TEMPLATES, get_template_plugins

    plugin_names = get_template_plugins("quick", "domain")
    # -> ["whois", "dns", "ip_geo", "http", "reputation"]
"""

# ─── Template definitions ─────────────────────────────────────────────────
# Each template is: { target_type: [plugin_name, ...] }
# The "full" template uses ALL_PLUGINS from runner.py (so we reference it by name only).

TEMPLATES: dict[str, dict[str, list[str]]] = {
    "full": {
        "domain": [
            "whois", "dns", "certs", "ip_geo", "http", "shodan", "wayback",
            "bgp", "reputation", "subdomains", "passive_dns", "pastes", "github_osint",
        ],
        "url": [
            "whois", "dns", "certs", "ip_geo", "http", "shodan", "wayback",
            "bgp", "reputation", "subdomains", "passive_dns", "github_osint",
        ],
        "ip": [
            "ip_geo", "dns", "shodan", "bgp", "reputation", "passive_dns",
        ],
        "email": [
            "email", "breach", "social_email", "github_osint", "pastes",
        ],
        "username": [
            "username", "profile", "github_osint", "pastes",
        ],
        "phone": ["phone"],
        "image": ["image"],
        "person": ["entity", "github_osint"],
        "company": ["entity", "github_osint"],
    },
    "quick": {
        "domain": ["dns", "whois", "ip_geo", "http", "reputation"],
        "url": ["dns", "whois", "ip_geo", "http", "reputation"],
        "ip": ["ip_geo", "dns", "reputation"],
        "email": ["email", "breach", "reputation"],
        "username": ["username"],
        "phone": ["phone"],
        "image": ["image"],
        "person": ["entity"],
        "company": ["entity"],
    },
    "email_intel": {
        "email": ["email", "breach", "social_email", "email_verify", "email_disposable"],
        "domain": ["dns"],
        "username": ["username"],
        "person": ["entity"],
        "company": ["entity"],
    },
    "brand": {
        "domain": ["subdomains", "certs", "wayback", "shodan", "reputation", "http"],
        "url": ["subdomains", "certs", "wayback", "shodan", "reputation", "http"],
        "ip": ["shodan", "reputation", "http"],
    },
    "person": {
        "person": ["entity", "username", "profile", "github_osint", "pastes"],
        "username": ["username", "profile", "github_osint", "pastes"],
        "email": ["email", "breach", "social_email", "github_osint", "pastes"],
        "phone": ["phone"],
    },
    # ─── Monster Mode: 5 new templates ──────────────────────────────────
    "brand_protection": {
        "domain": ["subdomains", "certs", "wayback", "shodan", "reputation", "http",
                   "typosquat", "ssl_analysis", "technology", "robots_sitemap", "port_scan"],
        "url": ["subdomains", "certs", "wayback", "shodan", "reputation", "http",
                "typosquat", "ssl_analysis", "technology", "robots_sitemap", "port_scan"],
        "ip": ["shodan", "reputation", "http", "ssl_analysis", "port_scan"],
        "username": ["username", "profile", "github_osint"],
    },
    "darkweb": {
        "domain": ["reputation", "pastes", "threatfox", "otx", "malwarebazaar",
                   "virustotal", "urlscan", "cobaltstrike", "secret_scanner"],
        "url": ["reputation", "pastes", "threatfox", "otx", "virustotal",
                "urlscan", "cobaltstrike", "secret_scanner"],
        "ip": ["reputation", "threatfox", "otx", "greynoise", "virustotal",
               "cobaltstrike", "jarm"],
        "email": ["breach", "email", "social_email", "pastes", "threatfox"],
        "hash": ["malwarebazaar", "threatfox"],
    },
    "pep_sanctions": {
        "person": ["entity", "opensanctions", "gdelt", "secedgar", "openalex", "crossref", "gleif"],
        "company": ["opencorporates", "opensanctions", "secedgar", "gleif", "gdelt"],
        "domain": ["whois", "dns", "http", "opensanctions"],
        "email": ["email", "breach", "opensanctions"],
    },
    "due_diligence": {
        "company": ["opencorporates", "secedgar", "gleif", "opensanctions", "gdelt",
                    "openalex", "crossref", "whois", "dns", "http"],
        "domain": ["whois", "dns", "http", "certs", "reputation", "ssl_analysis",
                   "technology", "vies"],
        "person": ["entity", "opensanctions", "gdelt", "secedgar", "openalex", "crossref"],
        "vat": ["vies"],
        "iban": ["iban"],
    },
    "c2_hunt": {
        "ip": ["reputation", "shodan", "greynoise", "jarm", "cobaltstrike",
               "threatfox", "otx", "virustotal", "ssl_analysis", "port_scan"],
        "domain": ["dns", "whois", "certs", "http", "jarm", "cobaltstrike",
                   "threatfox", "reputation", "ssl_analysis", "urlscan"],
        "url": ["dns", "http", "jarm", "cobaltstrike", "threatfox",
                "reputation", "urlscan", "redirect_chain"],
    },
}

# Map plugin name → plugin class for lookup
PLUGIN_NAME_MAP: dict[str, str] = {
    "whois": "plugins.whois_plugin.WhoisPlugin",
    "dns": "plugins.dns_plugin.DnsPlugin",
    "certs": "plugins.certs_plugin.CertsPlugin",
    "ip_geo": "plugins.ip_plugin.IpPlugin",
    "http": "plugins.http_plugin.HttpPlugin",
    "shodan": "plugins.shodan_plugin.ShodanPlugin",
    "wayback": "plugins.wayback_plugin.WaybackPlugin",
    "bgp": "plugins.bgp_plugin.BgpPlugin",
    "reputation": "plugins.reputation_plugin.ReputationPlugin",
    "subdomains": "plugins.subdomain_plugin.SubdomainPlugin",
    "passive_dns": "plugins.passivedns_plugin.PassiveDnsPlugin",
    "pastes": "plugins.pastebin_plugin.PastebinPlugin",
    "github_osint": "plugins.github_osint_plugin.GithubOsintPlugin",
    "email": "plugins.email_plugin.EmailPlugin",
    "breach": "plugins.breach_plugin.BreachPlugin",
    "social_email": "plugins.social_email_plugin.SocialEmailPlugin",
    "username": "plugins.username_plugin.UsernamePlugin",
    "phone": "plugins.phone_plugin.PhonePlugin",
    "image": "plugins.image_plugin.ImagePlugin",
    "profile": "plugins.profile_plugin.ProfilePlugin",
    "entity": "plugins.entity_plugin.EntityPlugin",
    "ai_analysis": "plugins.ai_analysis.AiAnalysisPlugin",
    # email_verify and email_disposable are virtual — handled within email plugin
    "email_verify": "plugins.email_plugin.EmailPlugin",
    "email_disposable": "plugins.email_plugin.EmailPlugin",
    # ─── Monster Mode: new plugins ────────────────────────────────────────
    "threatfox": "plugins.threatfox_plugin.ThreatFoxPlugin",
    "malwarebazaar": "plugins.malwarebazaar_plugin.MalwareBazaarPlugin",
    "urlscan": "plugins.urlscan_plugin.UrlScanPlugin",
    "virustotal": "plugins.virustotal_plugin.VirusTotalPlugin",
    "greynoise": "plugins.greynoise_plugin.GreyNoisePlugin",
    "opensanctions": "plugins.opensanctions_plugin.OpenSanctionsPlugin",
    "otx": "plugins.otx_plugin.OtxPlugin",
    "gdelt": "plugins.gdelt_plugin.GdeltPlugin",
    "opencorporates": "plugins.opencorporates_plugin.OpenCorporatesPlugin",
    "secedgar": "plugins.secedgar_plugin.SecEdgarPlugin",
    "gleif": "plugins.gleif_plugin.GleifPlugin",
    "vies": "plugins.vies_plugin.ViesPlugin",
    "openalex": "plugins.openalex_plugin.OpenAlexPlugin",
    "crossref": "plugins.crossref_plugin.CrossrefPlugin",
    "typosquat": "plugins.typosquat_plugin.TyposquatPlugin",
    "jarm": "plugins.jarm_plugin.JarmPlugin",
    "cobaltstrike": "plugins.cobaltstrike_plugin.CobaltstrikePlugin",
    "secret_scanner": "plugins.secret_scanner_plugin.SecretScannerPlugin",
    "iban": "plugins.iban_plugin.IbanPlugin",
    "vin": "plugins.vin_plugin.VinPlugin",
    "flight": "plugins.flight_plugin.FlightPlugin",
    "blockstream": "plugins.blockstream_plugin.BlockstreamPlugin",
    "etherscan": "plugins.etherscan_plugin.EtherscanPlugin",
    "mastodon": "plugins.mastodon_plugin.MastodonPlugin",
    "bluesky": "plugins.bluesky_plugin.BlueskyPlugin",
    "nostr": "plugins.nostr_plugin.NostrPlugin",
    "stackexchange": "plugins.stackexchange_plugin.StackExchangePlugin",
    "ens_resolver": "plugins.ens_resolver_plugin.EnsResolverPlugin",
}

# Cache of instantiated plugins
_plugin_cache: dict[str, object] = {}


def _import_plugin(name: str):
    """Lazy-import and cache a plugin instance by name."""
    if name in _plugin_cache:
        return _plugin_cache[name]

    path = PLUGIN_NAME_MAP.get(name)
    if not path:
        return None

    module_path, class_name = path.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    instance = cls()
    _plugin_cache[name] = instance
    return instance


def get_template_plugins(template_name: str, target_type: str) -> list:
    """
    Return a list of plugin instances for the given template + target_type.

    Raises KeyError if template_name is not found.
    Returns [] if target_type is not in the template.
    """
    tmpl = TEMPLATES.get(template_name)
    if not tmpl:
        raise KeyError(f"Template '{template_name}' not found. Available: {', '.join(TEMPLATES)}")

    plugin_names = tmpl.get(target_type, [])
    plugins = []
    for name in plugin_names:
        # Skip virtual plugins (email_verify, email_disposable are covered by email)
        if name in ("email_verify", "email_disposable"):
            continue
        p = _import_plugin(name)
        if p:
            plugins.append(p)
    return plugins


def list_templates() -> list[dict]:
    """Return all templates with their descriptions and plugin counts."""
    descriptions = {
        "full": "Run all available plugins for the target type",
        "quick": "Fast scan — DNS, WHOIS, IP geo, HTTP, reputation",
        "email_intel": "Deep email investigation — breach, social, verification",
        "brand": "Brand protection — subdomains, certs, wayback, shodan, reputation",
        "person": "Person investigation — entity, username, profiles, GitHub, pastes",
        # Monster Mode
        "brand_protection": "Typosquatting + SSL + subdomain sprawl + tech stack + reputation (defensive brand monitoring)",
        "darkweb": "Threat intel focus — abuse.ch, OTX, MalwareBazaar, Cobalt Strike, secret scanning",
        "pep_sanctions": "PEP & sanctions screening — OpenSanctions, GDELT, SEC, academic, LEI",
        "due_diligence": "Corporate KYC — OpenCorporates, SEC EDGAR, GLEIF, VIES VAT, sanctions, news",
        "c2_hunt": "C2 infrastructure hunting — JARM, Cobalt Strike, GreyNoise, Shodan, reputation, threat feeds",
    }
    result = []
    for name, mapping in TEMPLATES.items():
        result.append({
            "name": name,
            "description": descriptions.get(name, ""),
            "target_types": list(mapping.keys()),
            "plugins_per_type": {tt: len(plugins) for tt, plugins in mapping.items()},
        })
    return result