"""
Monitor bot commands — /monitor, /monitors, /unmonitor, /checkmon
"""
import aiohttp
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from config import get_settings
from bot.handlers.start import get_or_create_token

router = Router()
settings = get_settings()
API_BASE = f"http://localhost:{settings.api_port}/api/v1"

SCHEDULE_LABELS = {
    "hourly":  "⏱ Every hour",
    "daily":   "📅 Daily",
    "weekly":  "🗓 Weekly",
}


@router.message(Command("monitor"))
async def cmd_monitor(message: Message):
    args = message.text.split(maxsplit=2)
    if len(args) < 2:
        await message.answer(
            "📡 *Argus Monitor — Watch any target for changes*\n\n"
            "*Usage:*\n"
            "`/monitor <target> [schedule]`\n\n"
            "*Supported targets:*\n"
            "🌐 `github.com` — domain\n"
            "📧 `user@gmail.com` — email\n"
            "👤 `@username` — username (50+ platforms)\n"
            "🖥️ `8.8.8.8` — IP address\n\n"
            "*Schedules:* `hourly` · `daily` (default) · `weekly`\n\n"
            "*Examples:*\n"
            "`/monitor github.com daily`\n"
            "`/monitor user@gmail.com weekly`\n"
            "`/monitor @elonmusk daily`\n\n"
            "_Argus re-investigates on schedule and pings you only when something changes._",
            parse_mode="Markdown",
        )
        return

    target = args[1].strip()
    schedule = args[2].strip().lower() if len(args) > 2 else "daily"

    if schedule not in ("hourly", "daily", "weekly"):
        await message.answer(
            f"❌ Invalid schedule `{schedule}`.\n\nUse: `hourly` · `daily` · `weekly`",
            parse_mode="Markdown",
        )
        return

    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Auth failed — send /start")
        return

    from plugins.runner import classify_target
    target_type = classify_target(target)
    type_emoji = {
        "domain": "🌐", "url": "🔗", "ip": "🖥️", "email": "📧",
        "username": "👤", "phone": "📞", "image": "🖼️", "person": "🧑", "company": "🏢",
    }.get(target_type, "🔍")

    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            payload = {
                "target": target,
                "schedule": schedule,
                "telegram_chat_id": message.chat.id,
            }
            async with s.post(f"{API_BASE}/monitors", json=payload, headers=headers) as resp:
                if resp.status == 409:
                    await message.answer(
                        f"⚠️ Already monitoring `{target}`.\n\nCheck `/monitors` for your active monitors.",
                        parse_mode="Markdown",
                    )
                    return
                if resp.status not in (200, 201):
                    err = await resp.text()
                    await message.answer(f"❌ Failed to create monitor: {err}")
                    return
                data = await resp.json()

        mon_id = data.get("id")
        interval_label = SCHEDULE_LABELS.get(schedule, schedule)
        next_check = data.get("next_check", "")[:16].replace("T", " ") if data.get("next_check") else "soon"

        kb = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔍 Investigate Now", callback_data=f"argus_moncheck_{mon_id}"),
                InlineKeyboardButton(text="📜 My Monitors", callback_data="argus_monitors_0"),
            ],
            [
                InlineKeyboardButton(text="⏸ Pause", callback_data=f"argus_pause_mon_{mon_id}"),
                InlineKeyboardButton(text="🗑 Delete", callback_data=f"argus_del_mon_{mon_id}"),
            ],
        ])

        await message.answer(
            f"✅ *Monitor created!*\n\n"
            f"{type_emoji} Target: `{target}` ({target_type})\n"
            f"🕐 Schedule: {interval_label}\n"
            f"📋 Monitor ID: #{mon_id}\n"
            f"⏰ First check: {next_check} UTC\n\n"
            f"_I'll ping you here whenever something changes._",
            parse_mode="Markdown",
            reply_markup=kb,
        )

    except Exception as e:
        await message.answer(f"❌ Error: {e}")


@router.message(Command("monitors"))
async def cmd_monitors(message: Message):
    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Auth failed — send /start")
        return

    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.get(f"{API_BASE}/monitors", headers=headers) as resp:
                monitors = await resp.json()

        if not monitors:
            await message.answer(
                "📡 *No active monitors.*\n\n"
                "Start one with:\n`/monitor github.com daily`",
                parse_mode="Markdown",
            )
            return

        lines = ["📡 *Your Monitors*\n"]
        buttons = []

        for m in monitors:
            active_emoji = "✅" if m.get("active") else "⏸"
            type_emoji = {
                "domain": "🌐", "url": "🔗", "ip": "🖥️", "email": "📧",
                "username": "👤", "phone": "📞", "person": "🧑", "company": "🏢",
            }.get(m.get("target_type", ""), "🔍")

            last = m.get("last_checked", "Never")
            if last and last != "Never":
                last = last[:16].replace("T", " ") + " UTC"
            next_c = m.get("next_check", "?")
            if next_c and next_c != "?":
                next_c = next_c[:16].replace("T", " ") + " UTC"

            changes = m.get("change_count", 0)

            lines.append(
                f"{active_emoji} *#{m['id']}* {type_emoji} `{m['target']}`\n"
                f"   {SCHEDULE_LABELS.get(m.get('schedule', ''), m.get('schedule', ''))} | "
                f"Changes: {changes} | Last: {last}"
            )

            row = [
                InlineKeyboardButton(
                    text=f"{'▶️ Resume' if not m.get('active') else '⏸ Pause'} #{m['id']}",
                    callback_data=f"argus_{'resume' if not m.get('active') else 'pause'}_mon_{m['id']}",
                ),
                InlineKeyboardButton(
                    text=f"🔍 Check #{m['id']}",
                    callback_data=f"argus_moncheck_{m['id']}",
                ),
            ]
            buttons.append(row)

        buttons.append([
            InlineKeyboardButton(text="📜 History", callback_data="argus_history_0"),
        ])

        await message.answer(
            "\n".join(lines),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
        )

    except Exception as e:
        await message.answer(f"❌ Error: {e}")


@router.message(Command("unmonitor"))
async def cmd_unmonitor(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer(
            "Usage: `/unmonitor <id>`\n\nSee your monitors with /monitors",
            parse_mode="Markdown",
        )
        return

    mon_id = args[1].strip()
    if not mon_id.isdigit():
        await message.answer("❌ Please provide a numeric monitor ID.")
        return

    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Auth failed — send /start")
        return

    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.delete(f"{API_BASE}/monitors/{mon_id}", headers=headers) as resp:
                if resp.status == 404:
                    await message.answer("❌ Monitor not found.")
                    return
                if resp.status == 200:
                    await message.answer(
                        f"🗑 *Monitor #{mon_id} deleted.*\n\nYou won't receive further alerts for this target.",
                        parse_mode="Markdown",
                    )
    except Exception as e:
        await message.answer(f"❌ Error: {e}")


@router.message(Command("checkmon"))
async def cmd_checkmon(message: Message):
    """Force an immediate check on a monitor."""
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.answer("Usage: `/checkmon <monitor_id>`", parse_mode="Markdown")
        return

    mon_id = args[1].strip()
    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Auth failed — send /start")
        return

    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.post(f"{API_BASE}/monitors/{mon_id}/check-now", headers=headers) as resp:
                if resp.status == 404:
                    await message.answer("❌ Monitor not found.")
                    return
                await message.answer(
                    f"✅ Monitor #{mon_id} queued for immediate check.\n"
                    f"_You'll be notified if anything changed._",
                    parse_mode="Markdown",
                )
    except Exception as e:
        await message.answer(f"❌ Error: {e}")


# ── Callback handlers for monitor buttons ─────────────────────────────────────

@router.callback_query(F.data.startswith("argus_monitors_"))
async def cb_monitors_list(call: CallbackQuery):
    await call.answer()
    # Reuse the /monitors logic
    call.message.text = "/monitors"
    await cmd_monitors(call.message)


@router.callback_query(F.data.startswith("argus_pause_mon_"))
async def cb_pause_monitor(call: CallbackQuery):
    mon_id = call.data.split("_")[-1]
    await call.answer("Pausing monitor…")
    token = await get_or_create_token(call.message)
    if not token:
        await call.message.answer("❌ Auth failed")
        return
    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.patch(
                f"{API_BASE}/monitors/{mon_id}",
                json={"active": False},
                headers=headers,
            ) as resp:
                if resp.status == 200:
                    await call.message.answer(
                        f"⏸ *Monitor #{mon_id} paused.*\n"
                        f"Resume with /monitors → Resume button.",
                        parse_mode="Markdown",
                    )
    except Exception as e:
        await call.message.answer(f"❌ Error: {e}")


@router.callback_query(F.data.startswith("argus_resume_mon_"))
async def cb_resume_monitor(call: CallbackQuery):
    mon_id = call.data.split("_")[-1]
    await call.answer("Resuming monitor…")
    token = await get_or_create_token(call.message)
    if not token:
        await call.message.answer("❌ Auth failed")
        return
    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.patch(
                f"{API_BASE}/monitors/{mon_id}",
                json={"active": True},
                headers=headers,
            ) as resp:
                if resp.status == 200:
                    await call.message.answer(
                        f"▶️ *Monitor #{mon_id} resumed.*",
                        parse_mode="Markdown",
                    )
    except Exception as e:
        await call.message.answer(f"❌ Error: {e}")


@router.callback_query(F.data.startswith("argus_del_mon_"))
async def cb_delete_monitor(call: CallbackQuery):
    mon_id = call.data.split("_")[-1]
    await call.answer("Deleting…")
    token = await get_or_create_token(call.message)
    if not token:
        await call.message.answer("❌ Auth failed")
        return
    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.delete(f"{API_BASE}/monitors/{mon_id}", headers=headers) as resp:
                if resp.status == 200:
                    await call.message.answer(f"🗑 Monitor #{mon_id} deleted.")
    except Exception as e:
        await call.message.answer(f"❌ Error: {e}")


@router.callback_query(F.data.startswith("argus_moncheck_"))
async def cb_check_now(call: CallbackQuery):
    mon_id = call.data.split("_")[-1]
    await call.answer("Triggering check…")
    token = await get_or_create_token(call.message)
    if not token:
        await call.message.answer("❌ Auth failed")
        return
    try:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {token}"}
            async with s.post(f"{API_BASE}/monitors/{mon_id}/check-now", headers=headers) as resp:
                if resp.status == 200:
                    await call.message.answer(
                        f"🔍 Monitor #{mon_id} queued for immediate check.\n"
                        f"_I'll notify you if anything changed._",
                        parse_mode="Markdown",
                    )
    except Exception as e:
        await call.message.answer(f"❌ Error: {e}")
