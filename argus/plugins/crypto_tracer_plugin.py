import asyncio

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class CryptoTracerPlugin(BasePlugin):
    name = "crypto_tracer"
    description = "Blockchain address lookup for BTC and ETH balances and transactions"
    supported_target_types = ["crypto"]

    async def run(self, target: str) -> PluginResult:
        try:
            addr = target.strip()

            is_btc = addr.startswith(("1", "3", "bc1"))
            is_eth = addr.startswith("0x") and len(addr) == 42

            if not (is_btc or is_eth):
                return PluginResult(plugin_name=self.name, success=False, error="Unrecognized cryptocurrency address format")

            results: dict = {"address": addr, "currency": "BTC" if is_btc else "ETH"}

            if is_btc:
                await self._lookup_btc(addr, results)
            else:
                await self._lookup_eth(addr, results)

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))

    async def _lookup_btc(self, addr: str, results: dict):
        try:
            url = f"https://blockchain.info/q/addressbalance/{addr}"
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        try:
                            balance_sat = int(text)
                            results["balance_btc"] = balance_sat / 1e8
                        except ValueError:
                            results["balance_btc"] = None
        except Exception:
            results["balance_btc"] = None

        try:
            url = f"https://blockchain.info/rawaddr/{addr}?limit=1"
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results["total_transactions"] = data.get("n_tx", 0)
                        results["final_balance_btc"] = data.get("final_balance", 0) / 1e8
                        txs = data.get("txs", [])
                        if txs:
                            results["first_seen"] = txs[-1].get("time")
                            results["last_seen"] = txs[0].get("time")
        except Exception:
            pass

    async def _lookup_eth(self, addr: str, results: dict):
        # Etherscan free API (no key needed for basic lookups, but rate limited)
        try:
            url = f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&tag=latest"
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "1":
                            balance_wei = int(data.get("result", "0"))
                            results["balance_eth"] = balance_wei / 1e18
                        else:
                            results["balance_eth"] = None
        except Exception:
            results["balance_eth"] = None

        try:
            url = f"https://api.etherscan.io/api?module=account&action=txlist&address={addr}&startblock=0&endblock=99999999&sort=asc&offset=1&page=1"
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "1":
                            txs = data.get("result", [])
                            results["total_transactions"] = len(txs)
                            if txs:
                                results["first_seen"] = txs[0].get("timeStamp")
                                results["last_seen"] = txs[-1].get("timeStamp")
                        elif data.get("message") == "No transactions found":
                            results["total_transactions"] = 0
        except Exception:
            pass