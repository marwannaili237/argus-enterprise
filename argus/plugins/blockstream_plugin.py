"""
Blockstream.info BTC address lookup plugin — 100% free, no API key.
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

BTC_PATTERNS = [
    re.compile(r"^bc1[a-zA-HJ-NP-Z0-9]{25,62}$"),
    re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
]


class BlockstreamPlugin(BasePlugin):
    name = "blockstream"
    description = "BTC address lookup via Blockstream.info (balance, txs)"
    supported_target_types = ["crypto"]

    async def run(self, target: str) -> PluginResult:
        try:
            addr = target.strip()
            if not any(p.match(addr) for p in BTC_PATTERNS):
                return PluginResult(plugin_name=self.name, success=False, error="Not a BTC address")

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                # Address stats
                async with s.get(f"https://blockstream.info/api/address/{addr}", headers=HEADERS) as r:
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    info = await r.json(content_type=None)

                chain = info.get("chain_stats", {}) or {}
                mempool = info.get("mempool_stats", {}) or {}

                funded = int(chain.get("funded_txo_sum", 0)) + int(mempool.get("funded_txo_sum", 0))
                spent = int(chain.get("spent_txo_sum", 0)) + int(mempool.get("spent_txo_sum", 0))
                balance = funded - spent
                tx_count = int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))

                # Recent transactions
                recent_txs = []
                try:
                    async with s.get(f"https://blockstream.info/api/address/{addr}/txs", headers=HEADERS) as rt:
                        if rt.status == 200:
                            txs = await rt.json(content_type=None) or []
                            for tx in txs[:5]:
                                # Net value to this address
                                value = 0
                                for vin in tx.get("vin", []):
                                    if vin.get("prevout", {}) and vin["prevout"].get("scriptpubkey_address") == addr:
                                        value -= int(vin["prevout"].get("value", 0))
                                for vout in tx.get("vout", []):
                                    if vout.get("scriptpubkey_address") == addr:
                                        value += int(vout.get("value", 0))
                                status = tx.get("status", {}) or {}
                                recent_txs.append({
                                    "txid": tx.get("txid"),
                                    "value": value,
                                    "confirmed": bool(status.get("confirmed")),
                                    "block_height": status.get("block_height"),
                                })
                except Exception:
                    pass

            summary = (f"BTC address {addr}: balance={balance} sats ({balance/1e8:.8f} BTC), "
                       f"received={funded} sats, sent={spent} sats, txs={tx_count}")

            return PluginResult(plugin_name=self.name, success=True, data={
                "address": addr,
                "balance_satoshis": balance,
                "total_received_satoshis": funded,
                "total_sent_satoshis": spent,
                "tx_count": tx_count,
                "recent_txs": recent_txs,
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
