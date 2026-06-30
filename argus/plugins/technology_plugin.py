import asyncio
import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

# Wappalyzer-style technology signatures
HEADER_SIGNATURES = {
    "X-Powered-By": None,  # Value is the tech name
    "X-Drupal-Cache": "Drupal",
    "X-Generator": None,
    "X-AspNet-Version": "ASP.NET",
    "X-Pingback": None,
    "Server": None,
    "X-Magento-Version": "Magento",
    "X-Shopify-Stage": "Shopify",
    "X-Wix-Request-Id": "Wix",
    "X-Served-By": None,
    "X-Cache": None,
    "CF-Ray": "Cloudflare",
    "Fly-Request-Id": "Fly.io",
    "Vercel-Id": "Vercel",
    "X-Netlify-Id": "Netlify",
    "X-Amz-Cf-Id": "AWS CloudFront",
    "X-GitHub-Request-Id": "GitHub Pages",
    "X-Varnish": "Varnish",
    "X-Proxy-Id": "Reverse Proxy",
}

# HTML body patterns for technology detection
BODY_SIGNATURES = {
    "WordPress": [r'wp-content', r'wp-includes', r'<meta name="generator" content="WordPress'],
    "Joomla": [r'/media/jui/', r'<meta name="generator" content="Joomla'],
    "Drupal": [r'Drupal.settings', r'<meta name="Generator" content="Drupal'],
    "Laravel": [r'laravel_session', r'laravel_token'],
    "Django": [r'csrfmiddlewaretoken', r'django'],
    "React": [r'react\.js', r'react-dom', r'__NEXT_DATA__', r'_reactRoot'],
    "Vue.js": [r'vue\.js', r'v-cloak', r'v-bind', r'__VUE'],
    "Angular": [r'ng-app', r'ng-controller', r'angular\.js', r'[ngClass]'],
    "jQuery": [r'jquery[.-]\d', r'jQuery'],
    "Bootstrap": [r'bootstrap[.-]min\.css', r'bootstrap\.js'],
    "Tailwind CSS": [r'tailwind\.css', r'tailwindcss'],
    "Next.js": [r'__NEXT_DATA__', r'_next/static'],
    "Nuxt.js": [r'__NUXT__', r'_nuxt/'],
    "Gatsby": [r'gatsby', r'___GATSBY'],
    "Hugo": [r'Hugo', r'generator.*Hugo'],
    "Ghost": [r'ghost\.org', r'<meta name="generator" content="Ghost'],
    "Shopify": [r'shopify\.com', r'Shopify\.theme'],
    "WooCommerce": [r'woocommerce', r'WooCommerce'],
    "phpMyAdmin": [r'phpmyadmin', r'pma_'],
    "cPanel": [r'cPanel', r'cpanel'],
    "Cloudflare": [r'cloudflare', r'cf-browser-verification'],
    "Google Analytics": [r'google-analytics\.com', r'gtag\(', r'GA_'],
    "Google Tag Manager": [r'googletagmanager\.com', r'GTM-'],
    "Matomo": [r'matomo\.', r'piwik\.'],
    "Nginx": [r'<center>nginx</center>', r'nginx/'],
    "Apache": [r'Apache/[\d]', r'mod_'],
    "OpenResty": [r'openresty'],
    "CloudFront": [r'cloudfront\.net'],
    "Varnish": [r'X-Varnish', r'varnish'],
    "Chart.js": [r'chart\.js', r'Chart\.js'],
    "Three.js": [r'three\.js', r'THREE\.WebGL'],
    "Font Awesome": [r'font-awesome', r'fontawesome'],
    "React Router": [r'react-router', r'ReactRouter'],
}


class TechnologyPlugin(BasePlugin):
    name = "technology"
    description = "Enhanced technology detection via headers and HTML body analysis"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            url = target
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            results: dict = {"target": target, "url": url, "technologies": [], "categories": {}}

            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as session:
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as resp:
                        headers = dict(resp.headers)
                        body = await resp.text(errors="ignore")[:200000]
                        status = resp.status
                except Exception:
                    # Try HTTP
                    url = url.replace("https://", "http://")
                    async with session.get(url, ssl=False, allow_redirects=True) as resp:
                        headers = dict(resp.headers)
                        body = await resp.text(errors="ignore")[:200000]
                        status = resp.status

            results["status_code"] = status
            found_techs: dict[str, dict] = {}

            # Header-based detection
            for header, tech_name in HEADER_SIGNATURES.items():
                value = headers.get(header)
                if value:
                    detected_name = tech_name or value.split("/")[0].strip()
                    if detected_name not in found_techs:
                        found_techs[detected_name] = {"source": f"header ({header})", "value": value[:100]}

            # X-Powered-By is common and informative
            xpb = headers.get("X-Powered-By", "")
            if xpb:
                for tech in ["PHP", "Express", "Puma", "Phusion Passenger", "ASP.NET", "Next.js"]:
                    if tech.lower() in xpb.lower() and tech not in found_techs:
                        found_techs[tech] = {"source": "header (X-Powered-By)", "value": xpb}

            # Server header analysis
            server = headers.get("Server", "")
            if server:
                server_lower = server.lower()
                if "cloudflare" in server_lower and "Cloudflare" not in found_techs:
                    found_techs["Cloudflare"] = {"source": "header (Server)", "value": server}
                if "nginx" in server_lower and "Nginx" not in found_techs:
                    found_techs["Nginx"] = {"source": "header (Server)", "value": server}
                if "apache" in server_lower and "Apache" not in found_techs:
                    found_techs["Apache"] = {"source": "header (Server)", "value": server}
                if "openresty" in server_lower and "OpenResty" not in found_techs:
                    found_techs["OpenResty"] = {"source": "header (Server)", "value": server}

            # Body-based detection
            for tech_name, patterns in BODY_SIGNATURES.items():
                if tech_name in found_techs:
                    continue
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        found_techs[tech_name] = {"source": "body pattern"}
                        break

            # Categorize
            categories: dict[str, list[str]] = {
                "cms": [], "framework": [], "frontend": [], "analytics": [],
                "hosting": [], "server": [], "library": [], "other": [],
            }

            CMS_TECHS = {"WordPress", "Joomla", "Drupal", "Ghost", "Shopify", "WooCommerce", "Magento"}
            FRAMEWORK_TECHS = {"Laravel", "Django", "React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Gatsby", "Hugo", "ASP.NET", "Express", "Flask", "Rails"}
            FRONTEND_TECHS = {"jQuery", "Bootstrap", "Tailwind CSS", "Chart.js", "Three.js", "Font Awesome", "React Router"}
            ANALYTICS_TECHS = {"Google Analytics", "Google Tag Manager", "Matomo"}
            HOSTING_TECHS = {"Cloudflare", "Vercel", "Netlify", "GitHub Pages", "AWS CloudFront", "Fly.io"}
            SERVER_TECHS = {"Nginx", "Apache", "OpenResty", "Varnish", "cPanel", "phpMyAdmin", "CloudFront"}
            LIBRARY_TECHS = {"PHP", "Python", "Node.js", "Ruby"}

            for tech, info in found_techs.items():
                if tech in CMS_TECHS:
                    categories["cms"].append(tech)
                elif tech in FRAMEWORK_TECHS:
                    categories["framework"].append(tech)
                elif tech in FRONTEND_TECHS:
                    categories["frontend"].append(tech)
                elif tech in ANALYTICS_TECHS:
                    categories["analytics"].append(tech)
                elif tech in HOSTING_TECHS:
                    categories["hosting"].append(tech)
                elif tech in SERVER_TECHS:
                    categories["server"].append(tech)
                elif tech in LIBRARY_TECHS:
                    categories["library"].append(tech)
                else:
                    categories["other"].append(tech)

            categories = {k: v for k, v in categories.items() if v}
            results["technologies"] = list(found_techs.keys())
            results["details"] = found_techs
            results["categories"] = categories
            results["total"] = len(found_techs)

            if not found_techs:
                return PluginResult(plugin_name=self.name, success=False, error="No technologies detected")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))