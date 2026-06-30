import asyncio
import dns.resolver
import dns.dnssec

from plugins.base import BasePlugin, PluginResult


class DnssecPlugin(BasePlugin):
    name = "dnssec"
    description = "DNSSEC validation and chain of trust verification"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            results: dict = {"domain": domain, "dnssec_enabled": False, "validated": False, "details": {}}

            # Query DNSKEY
            def query_dnskey():
                try:
                    answers = resolver.resolve(domain, "DNSKEY")
                    keys = []
                    for r in answers:
                        flags = []
                        if r.flags & 0x0001:
                            flags.append("SEP")
                        if r.flags & 0x0100:
                            flags.append("REVOKE")
                        keys.append({
                            "flags": int(r.flags),
                            "flag_names": flags,
                            "protocol": r.protocol,
                            "algorithm": r.algorithm,
                            "key_tag": r.key_tag(),
                            "key_length": len(r.key) * 8,
                        })
                    return keys
                except Exception as e:
                    return str(e)

            # Query DS record
            def query_ds():
                try:
                    answers = resolver.resolve(domain, "DS")
                    records = []
                    for r in answers:
                        records.append({
                            "key_tag": r.key_tag,
                            "algorithm": r.algorithm,
                            "digest_type": r.digest_type,
                            "digest": r.digest.hex(),
                        })
                    return records
                except Exception as e:
                    return str(e)

            # Query RRSIG
            def query_rrsig():
                try:
                    answers = resolver.resolve(domain, "RRSIG")
                    records = []
                    for r in answers:
                        records.append({
                            "type_covered": r.type_covered,
                            "algorithm": r.algorithm,
                            "labels": r.labels,
                            "inception": str(r.inception),
                            "expiration": str(r.expiration),
                            "key_tag": r.key_tag,
                            "signer": str(r.signer),
                        })
                    return records
                except Exception as e:
                    return str(e)

            # Check with dnspython's DNSSEC validator
            def validate_dnssec():
                try:
                    answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
                    return dns.dnssec.validate(answer)
                except dns.dnssec.ValidationFailure as e:
                    return f"Validation failure: {e}"
                except Exception as e:
                    return str(e)

            dnskey_result, ds_result, rrsig_result, validation_result = await asyncio.gather(
                loop.run_in_executor(None, query_dnskey),
                loop.run_in_executor(None, query_ds),
                loop.run_in_executor(None, query_rrsig),
                loop.run_in_executor(None, validate_dnssec),
            )

            results["details"]["dnskey"] = dnskey_result
            results["details"]["ds"] = ds_result
            results["details"]["rrsig"] = rrsig_result
            results["details"]["validation"] = str(validation_result)

            # Determine DNSSEC status
            has_dnskey = isinstance(dnskey_result, list) and len(dnskey_result) > 0
            has_ds = isinstance(ds_result, list) and len(ds_result) > 0
            has_rrsig = isinstance(rrsig_result, list) and len(rrsig_result) > 0
            validation_ok = isinstance(validation_result, dns.rrset.RRset)

            results["dnssec_enabled"] = has_dnskey or has_rrsig
            results["has_dnskey"] = has_dnskey
            results["has_ds"] = has_ds
            results["has_rrsig"] = has_rrsig
            results["validated"] = validation_ok
            results["dnskey_count"] = len(dnskey_result) if isinstance(dnskey_result, list) else 0
            results["ds_count"] = len(ds_result) if isinstance(ds_result, list) else 0

            if not has_dnskey:
                return PluginResult(plugin_name=self.name, success=False, error="DNSSEC not enabled for this domain")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))