import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

# Common PDF metadata key patterns (binary/object structure)
PDF_META_PATTERNS = {
    "Author": re.compile(rb"/Author\s*\(([^)]*)\)"),
    "Creator": re.compile(rb"/Creator\s*\(([^)]*)\)"),
    "Producer": re.compile(rb"/Producer\s*\(([^)]*)\)"),
    "CreationDate": re.compile(rb"/CreationDate\s*\(([^)]*)\)"),
    "ModDate": re.compile(rb"/ModDate\s*\(([^)]*)\)"),
    "Title": re.compile(rb"/Title\s*\(([^)]*)\)"),
    "Subject": re.compile(rb"/Subject\s*\(([^)]*)\)"),
    "Keywords": re.compile(rb"/Keywords\s*\(([^)]*)\)"),
}

# Also try string-delimited patterns
PDF_META_STRING_PATTERNS = {
    "Author": re.compile(rb"/Author\s*/([^\s/>]+)"),
    "Creator": re.compile(rb"/Creator\s*/([^\s/>]+)"),
    "Producer": re.compile(rb"/Producer\s*/([^\s/>]+)"),
    "CreationDate": re.compile(rb"/CreationDate\s*/([^\s/>]+)"),
    "ModDate": re.compile(rb"/ModDate\s*/([^\s/>]+)"),
}


class PdfMetadataPlugin(BasePlugin):
    name = "pdf_metadata"
    description = "PDF metadata extraction from binary header analysis"
    supported_target_types = ["url"]

    async def run(self, target: str) -> PluginResult:
        try:
            url = target.strip()
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            if not url.lower().split("?")[0].endswith(".pdf"):
                return PluginResult(plugin_name=self.name, success=False, error="Target URL does not point to a PDF file")

            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {resp.status}")

                    # Read first 64KB for metadata
                    chunk = await resp.content.read(65536)

            if not chunk[:5].startswith(b"%PDF-"):
                return PluginResult(plugin_name=self.name, success=False, error="File does not appear to be a valid PDF")

            version = chunk[:8].decode("latin-1", errors="ignore").strip()
            metadata: dict = {"url": url, "pdf_version": version, "metadata": {}, "file_size_downloaded": len(chunk)}

            # Try parenthesis-delimited patterns first
            for key, pattern in PDF_META_PATTERNS.items():
                match = pattern.search(chunk)
                if match:
                    metadata["metadata"][key] = match.group(1).decode("latin-1", errors="ignore")

            # Fall back to string-delimited patterns
            for key, pattern in PDF_META_STRING_PATTERNS.items():
                if key not in metadata["metadata"]:
                    match = pattern.search(chunk)
                    if match:
                        metadata["metadata"][key] = match.group(1).decode("latin-1", errors="ignore")

            if not metadata["metadata"]:
                return PluginResult(plugin_name=self.name, success=False, error="No metadata found in PDF header")

            return PluginResult(plugin_name=self.name, success=True, data=metadata)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))