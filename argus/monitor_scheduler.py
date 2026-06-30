"""
Argus Monitor Scheduler — background asyncio loop that checks monitors
on schedule, runs fresh investigations, diffs results, and fires Telegram
alerts when anything changes.
"""
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from database import AsyncSessionLocal
from models import Monitor, Investigation, Evidence, User

logger = logging.getLogger("argus.monitor")

# How often the scheduler wakes up to check for due monitors (minutes)
POLL_INTERVAL_SECONDS = 300  # every 5 minutes


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _compute_fingerprint(evidence_list: list) -> str:
    """
    Compute a deterministic fingerprint of key OSINT metrics for change detection.
    Returns a SHA-256 hex digest.
    """
    key_data = {}

    for ev in evidence_list:
        plugin = ev.plugin_name
        d = ev.data or {}

        if plugin == "subdomains":
            key_data["subdomains"] = sorted(d.get("subdomains", []))
            key_data["subdomain_count"] = d.get("total_found", 0)

        elif plugin == "shodan":
            key_data["open_ports"] = sorted(d.get("all_open_ports", []))
            key_data["cves"] = sorted(d.get("all_vulns", []))
            key_data["shodan_tags"] = sorted(d.get("all_tags", []))

        elif plugin == "reputation":
            key_data["threats"] = sorted(d.get("threats", []))
            key_data["is_tor"] = d.get("is_tor_exit", False)

        elif plugin == "breach":
            key_data["breach_found"] = d.get("breach_found", False)
            key_data["credentials_leaked"] = d.get("credentials_leaked", False)
            key_data["risk_level"] = d.get("risk_level", "")

        elif plugin == "email":
            key_data["email_reputation"] = d.get("reputation", "")
            key_data["email_blacklisted"] = d.get("blacklisted", False)

        elif plugin == "username":
            key_data["platforms"] = sorted(p["platform"] for p in d.get("profiles", []))
            key_data["found_count"] = d.get("found_count", 0)

        elif plugin == "ip_geo":
            key_data["ip"] = d.get("ip")
            key_data["is_proxy"] = d.get("is_proxy", False)

        elif plugin == "certs":
            key_data["cert_count"] = d.get("total_certs", 0)
            key_data["subdomain_count_certs"] = d.get("total_subdomains", 0)

        elif plugin == "dns":
            records = d.get("records", {})
            key_data["dns_a"] = sorted(records.get("A", []))
            key_data["dns_mx"] = sorted(records.get("MX", []))

        elif plugin == "bgp":
            key_data["asn"] = d.get("asn")
            key_data["prefix"] = d.get("prefix")

        elif plugin == "social_email":
            key_data["social_count"] = d.get("registered_count", 0)
            key_data["social_platforms"] = sorted(
                item["site"] for item in d.get("registered_on", [])
            )

        elif plugin == "profile":
            key_data["profile_platforms"] = sorted(d.get("platforms_found", []))

    serialised = json.dumps(key_data, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def _compute_diff(old_evidence: list, new_evidence: list) -> list[str]:
    """
    Compute human-readable change descriptions between two investigation evidence sets.
    Returns a list of change strings.
    """
    changes = []

    def _by_plugin(evs):
        return {ev.plugin_name: ev.data or {} for ev in evs}

    old = _by_plugin(old_evidence)
    new = _by_plugin(new_evidence)

    # Subdomains
    old_subs = set(old.get("subdomains", {}).get("subdomains", []))
    new_subs = set(new.get("subdomains", {}).get("subdomains", []))
    added_subs = new_subs - old_subs
    removed_subs = old_subs - new_subs
    if added_subs:
        sample = list(added_subs)[:5]
        changes.append(f"🌐 *New subdomains* (+{len(added_subs)}): {', '.join(sample)}")
    if removed_subs:
        changes.append(f"🌐 *Subdomains removed* (-{len(removed_subs)})")

    # CVEs
    old_cves = set(old.get("shodan", {}).get("all_vulns", []))
    new_cves = set(new.get("shodan", {}).get("all_vulns", []))
    new_cve_list = new_cves - old_cves
    if new_cve_list:
        changes.append(f"🚨 *New CVEs detected*: {', '.join(list(new_cve_list)[:5])}")
    fixed_cves = old_cves - new_cves
    if fixed_cves:
        changes.append(f"✅ *CVEs resolved*: {', '.join(list(fixed_cves)[:3])}")

    # Open ports
    old_ports = set(old.get("shodan", {}).get("all_open_ports", []))
    new_ports = set(new.get("shodan", {}).get("all_open_ports", []))
    opened = new_ports - old_ports
    closed = old_ports - new_ports
    if opened:
        changes.append(f"🔌 *New open ports*: {', '.join(str(p) for p in sorted(opened))}")
    if closed:
        changes.append(f"🔒 *Ports closed*: {', '.join(str(p) for p in sorted(closed))}")

    # Breach status
    old_breach = old.get("breach", {}).get("breach_found", False)
    new_breach = new.get("breach", {}).get("breach_found", False)
    if new_breach and not old_breach:
        changes.append("🔓 *NEW DATA BREACH DETECTED* — credentials may be exposed!")
    old_creds = old.get("breach", {}).get("credentials_leaked", False)
    new_creds = new.get("breach", {}).get("credentials_leaked", False)
    if new_creds and not old_creds:
        changes.append("⚠️ *Credentials/passwords now appear in breach databases!*")

    # Threat reputation
    old_threats = set(old.get("reputation", {}).get("threats", []))
    new_threats = set(new.get("reputation", {}).get("threats", []))
    new_threat_list = new_threats - old_threats
    if new_threat_list:
        changes.append(f"🚨 *New threat flags*: {'; '.join(list(new_threat_list)[:3])}")

    # TOR exit node status
    old_tor = old.get("reputation", {}).get("is_tor_exit", False)
    new_tor = new.get("reputation", {}).get("is_tor_exit", False)
    if new_tor and not old_tor:
        changes.append("🧅 *IP is now a TOR exit node*")
    elif not new_tor and old_tor:
        changes.append("🧅 IP is no longer a TOR exit node")

    # IP address change
    old_ip = old.get("ip_geo", {}).get("ip")
    new_ip = new.get("ip_geo", {}).get("ip")
    if old_ip and new_ip and old_ip != new_ip:
        changes.append(f"📍 *IP changed*: {old_ip} → {new_ip}")

    # Username new platforms
    old_platforms = set(p["platform"] for p in old.get("username", {}).get("profiles", []))
    new_platforms = set(p["platform"] for p in new.get("username", {}).get("profiles", []))
    new_platform_list = new_platforms - old_platforms
    gone_platforms = old_platforms - new_platforms
    if new_platform_list:
        changes.append(f"👤 *New profiles found*: {', '.join(sorted(new_platform_list))}")
    if gone_platforms:
        changes.append(f"👤 *Profiles removed*: {', '.join(sorted(gone_platforms))}")

    # Social email new registrations
    old_social = set(item["site"] for item in old.get("social_email", {}).get("registered_on", []))
    new_social = set(item["site"] for item in new.get("social_email", {}).get("registered_on", []))
    new_social_list = new_social - old_social
    if new_social_list:
        changes.append(f"🔗 *Email newly registered on*: {', '.join(sorted(new_social_list))}")

    # DNS changes
    old_a = set(old.get("dns", {}).get("records", {}).get("A", []))
    new_a = set(new.get("dns", {}).get("records", {}).get("A", []))
    if old_a and new_a and old_a != new_a:
        added_a = new_a - old_a
        removed_a = old_a - new_a
        if added_a:
            changes.append(f"🌐 *New DNS A records*: {', '.join(sorted(added_a))}")
        if removed_a:
            changes.append(f"🌐 *DNS A records removed*: {', '.join(sorted(removed_a))}")

    # Certificate count
    old_cert_count = old.get("certs", {}).get("total_certs", 0)
    new_cert_count = new.get("certs", {}).get("total_certs", 0)
    if new_cert_count > old_cert_count + 5:
        changes.append(f"🔐 *{new_cert_count - old_cert_count} new SSL certificates issued*")

    return changes


async def _send_change_alert(
    monitor: Monitor,
    changes: list[str],
    new_inv_id: int,
    settings,
):
    """Send Telegram change alert with inline keyboard."""
    if not changes:
        return

    import aiohttp
    import json as _json

    text = (
        f"🔔 *Argus Monitor Alert*\n"
        f"Target: `{monitor.target}`\n"
        f"Schedule: {monitor.schedule}\n\n"
        f"*{len(changes)} change(s) detected:*\n\n"
        + "\n".join(f"• {c}" for c in changes[:10])
        + f"\n\n_Investigation #{new_inv_id}_"
    )

    if len(text) > 4000:
        text = text[:3997] + "…"

    keyboard = _json.dumps({
        "inline_keyboard": [
            [
                {"text": "📋 Full Results", "callback_data": f"argus_results_{new_inv_id}"},
                {"text": "🤖 AI Report", "callback_data": f"argus_analyze_{new_inv_id}"},
            ],
            [
                {"text": "🔁 Re-investigate Now", "callback_data": f"argus_reinvest_{new_inv_id}"},
                {"text": "⏸ Pause Monitor", "callback_data": f"argus_pause_mon_{monitor.id}"},
            ],
        ]
    })

    try:
        async with aiohttp.ClientSession() as s:
            await s.post(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                json={
                    "chat_id": monitor.telegram_chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "reply_markup": keyboard,
                },
            )
    except Exception as e:
        logger.error(f"Failed to send monitor alert: {e}")


async def _run_monitor(monitor: Monitor, settings):
    """Run a single monitor check."""
    logger.info(f"[Monitor #{monitor.id}] Checking {monitor.target}")

    async with AsyncSessionLocal() as db:
        # Get the user (needed to create investigation)
        user_result = await db.execute(select(User).where(User.id == monitor.user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            return

        # Create a fresh investigation (no Telegram message — alert comes separately)
        from models import Investigation as Inv
        from plugins.runner import classify_target, run_investigation

        new_inv = Inv(
            user_id=monitor.user_id,
            target=monitor.target,
            target_type=monitor.target_type,
            status="running",
            telegram_chat_id=None,
            telegram_message_id=None,
        )
        db.add(new_inv)
        await db.commit()
        await db.refresh(new_inv)
        new_inv_id = new_inv.id

    # Run investigation (no Telegram notification)
    await run_investigation(new_inv_id)

    # Now compare fingerprints
    async with AsyncSessionLocal() as db:
        # Get new evidence
        ev_result = await db.execute(
            select(Evidence).where(Evidence.investigation_id == new_inv_id)
        )
        new_evidence = ev_result.scalars().all()
        new_hash = _compute_fingerprint(new_evidence)

        # Get old evidence if we have a previous investigation
        old_evidence = []
        if monitor.last_investigation_id:
            old_ev_result = await db.execute(
                select(Evidence).where(Evidence.investigation_id == monitor.last_investigation_id)
            )
            old_evidence = old_ev_result.scalars().all()

        # Detect changes
        changes = []
        if monitor.last_hash and monitor.last_hash != new_hash:
            changes = _compute_diff(old_evidence, new_evidence)
            if not changes:
                changes = ["📊 Data has changed since last check (details in full results)"]

        # Update monitor record
        mon_result = await db.execute(select(Monitor).where(Monitor.id == monitor.id))
        mon = mon_result.scalar_one_or_none()
        if mon:
            mon.last_checked = _utcnow()
            mon.next_check = _utcnow() + timedelta(hours=mon.interval_hours)
            mon.last_hash = new_hash
            mon.last_investigation_id = new_inv_id
            if changes:
                mon.change_count = (mon.change_count or 0) + 1
            await db.commit()

        # Send alert if changes found
        if changes:
            logger.info(f"[Monitor #{monitor.id}] {len(changes)} change(s) detected for {monitor.target}")
            await _send_change_alert(monitor, changes, new_inv_id, settings)

            # Task 10: Webhook notification
            if monitor.webhook_url:
                from notifiers.webhook import WebhookNotifier
                webhook = WebhookNotifier(monitor.webhook_url)
                await webhook.notify_monitor_alert(
                    target=monitor.target,
                    changes=changes,
                    monitor_id=monitor.id,
                    investigation_id=new_inv_id,
                )
        else:
            logger.info(f"[Monitor #{monitor.id}] No changes for {monitor.target}")


async def run_scheduler(settings):
    """
    Main scheduler loop — checks every POLL_INTERVAL_SECONDS for due monitors.
    """
    logger.info("Monitor scheduler started")
    while True:
        try:
            async with AsyncSessionLocal() as db:
                due = await db.execute(
                    select(Monitor).where(
                        Monitor.active == True,
                        Monitor.next_check <= _utcnow(),
                    )
                )
                due_monitors = due.scalars().all()

            if due_monitors:
                logger.info(f"Running {len(due_monitors)} due monitor(s)")
                tasks = [_run_monitor(m, settings) for m in due_monitors]
                await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            logger.error(f"Scheduler error: {e}")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)
