"""
Etherscan / public RPC ETH address lookup plugin — free.
Uses ETHERSCAN_API_KEY env var if set, otherwise falls back to public RPC.
"""
import os
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
ETH_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
PUBLIC_RPC = "https://eth.public-rpc.com"


class EtherscanPlugin(BasePlugin):
    name = "etherscan"
    description = "ETH address balance & tx count via Etherscan (key) or public RPC"
    supported_target_types = ["crypto"]

    async def run(self, target: str) -> PluginResult:
        try:
            addr = target.strip()
            if not ETH_PATTERN.match(addr):
                return PluginResult(plugin_name=self.name, success=False, error="Not an ETH address")

            api_key = os.getenv("ETHERSCAN_API_KEY", "").strip()
            if api_key:
                return await self._via_etherscan(addr, api_key)
            return await self._via_public_rpc(addr)
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))

    async def _via_etherscan(self, addr: str, api_key: str) -> PluginResult:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            # Balance
            balance_wei = 0
            async with s.get(
                f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&tag=latest&apikey={api_key}",
                headers=HEADERS,
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    if str(data.get("status", "0")) == "1":
                        balance_wei = int(data.get("result", "0"))
                    else:
                        return PluginResult(plugin_name=self.name, success=False,
                                            error=f"Etherscan: {data.get('message', 'error')}")
                else:
                    return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")

            # Tx count
            tx_count = 0
            try:
                async with s.get(
                    f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={addr}&tag=latest&apikey={api_key}",
                    headers=HEADERS,
                ) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        hex_val = data.get("result", "0x0")
                        tx_count = int(hex_val, 16)
            except Exception:
                pass

        balance_eth = balance_wei / 1e18
        summary = f"ETH address {addr}: balance={balance_wei} wei ({balance_eth:.6f} ETH), tx_count={tx_count}"
        return PluginResult(plugin_name=self.name, success=True, data={
            "address": addr,
            "balance_wei": balance_wei,
            "balance_eth": balance_eth,
            "tx_count": tx_count,
            "source": "etherscan",
            "summary": summary,
        })

    async def _via_public_rpc(self, addr: str) -> PluginResult:
        payload_balance = {
            "jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": 1,
        }
        payload_txs = {
            "jsonrpc": "2.0", "method": "eth_getTransactionCount", "params": [addr, "latest"], "id": 2,
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            balance_wei = 0
            async with s.post(PUBLIC_RPC, json=payload_balance, headers=HEADERS) as r:
                if r.status != 200:
                    return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                data = await r.json(content_type=None)
                hex_balance = data.get("result", "0x0")
                if hex_balance and hex_balance.startswith("0x"):
                    balance_wei = int(hex_balance, 16)

            tx_count = 0
            try:
                async with s.post(PUBLIC_RPC, json=payload_txs, headers=HEADERS) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        hex_val = data.get("result", "0x0")
                        if hex_val and hex_val.startswith("0x"):
                            tx_count = int(hex_val, 16)
            except Exception:
                pass

        balance_eth = balance_wei / 1e18
        summary = f"ETH address {addr}: balance={balance_wei} wei ({balance_eth:.6f} ETH), tx_count={tx_count}"
        return PluginResult(plugin_name=self.name, success=True, data={
            "address": addr,
            "balance_wei": balance_wei,
            "balance_eth": balance_eth,
            "tx_count": tx_count,
            "source": "public_rpc",
            "summary": summary,
        })
