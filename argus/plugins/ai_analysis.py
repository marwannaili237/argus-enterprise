"""
Gemini AI analysis plugin — synthesizes all OSINT evidence into an
intelligence report with risk assessment, key findings, and recommendations.
Uses the new google-genai SDK.
"""
import os
import json
import asyncio
from plugins.base import BasePlugin, PluginResult

SYSTEM_PROMPT = """You are an expert OSINT analyst and cybersecurity intelligence officer.
You receive raw data collected from free public sources about a target (domain, IP, email, username, phone number, or image).
Your job is to synthesize this data into a concise, actionable threat intelligence report.

Format your response with these sections:
1. **Executive Summary** (2-3 sentences max)
2. **Key Findings** (bullet list of the most important discoveries)
3. **Risk Assessment** (Low / Medium / High / Critical — with brief justification)
4. **Notable IOCs** (Indicators of Compromise or interest — IPs, subdomains, emails, registrars, platform profiles)
5. **Recommendations** (2-3 actionable next steps for an analyst)

Be factual, concise, and use a professional intelligence report tone. Do not speculate beyond the data provided."""


class AiAnalysisPlugin(BasePlugin):
    name = "ai_analysis"
    description = "Gemini AI synthesizes all evidence into a threat intelligence report"
    supported_target_types = ["domain", "url", "ip", "email", "username", "phone", "image", "unknown"]

    def __init__(self):
        self._api_key = os.getenv("GEMINI_API_KEY", "")
        self._configured = bool(self._api_key)

    async def run(self, target: str, evidence_data: dict | None = None) -> PluginResult:
        if not self._configured:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error="GEMINI_API_KEY not configured",
            )

        try:
            from google import genai
            from google.genai import types

            evidence_str = json.dumps(evidence_data or {}, indent=2, default=str)
            prompt = f"""Target: {target}

Raw OSINT evidence collected:
{evidence_str}

Please analyze this data and produce a threat intelligence report."""

            loop = asyncio.get_event_loop()

            def _generate():
                client = genai.Client(api_key=self._api_key)
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        max_output_tokens=1024,
                        temperature=0.3,
                    ),
                )
                return response.text

            report = await loop.run_in_executor(None, _generate)

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={"report": report, "model": "gemini-2.0-flash"},
            )

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
