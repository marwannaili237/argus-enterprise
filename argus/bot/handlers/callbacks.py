"""
Inline keyboard callback handler — responds to button presses on investigation messages.
Callback data format: argus_{action}_{inv_id}
Actions: results, analyze, reinvest, history, cancel
"""
import aiohttp
from aiogram import Router, F
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from config import get_settings
from bot.handlers.start import get_or_create_token
from bot.handlers.results import _chunk_text

router = Router()
settings = get_settings()
API_BASE = f"http://localhost:{settings.api_port}/api/v1"


def _parse_cb(data: str):
    """Parse 'argus_{action}_{inv_id}' → (action, inv_id)"""
    parts = data.split("_", 2)
    if len(parts) == 3 and parts[0] == "argus":
        return parts[1], parts[2]
    return None, None


def results_keyboard(inv_id: str | int, has_ai: bool = True) -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="📋 Full Results", callback_data=f"argus_results_{inv_id}"),
        ]
    ]
    if has_ai:
        buttons[0].append(
            InlineKeyboardButton(text="🤖 AI Report", callback_data=f"argus_analyze_{inv_id}")
        )
    buttons.append([
        InlineKeyboardButton(text="🔁 Re-investigate", callback_data=f"argus_reinvest_{inv_id}"),
        InlineKeyboardButton(text="📜 History", callback_data=f"argus_history_0"),
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def running_keyboard(inv_id: str | int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="⏳ Check Status", callback_data=f"argus_status_{inv_id}"),
        InlineKeyboardButton(text="📜 History", callback_data=f"argus_history_0"),
    ]])


@router.callback_query(F.data.startswith("argus_"))
async def handle_callback(call: CallbackQuery):
    action, inv_id = _parse_cb(call.data)
    if not action:
        await call.answer("Unknown action", show_alert=False)
        return

    token = await get_or_create_token(call.message)
    if not token:
        await call.answer("❌ Auth failed — send /start", show_alert=True)
        return

    # ── History ───────────────────────────────────────────────────────────
    if action == "history":
        await call.answer()
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations?limit=10", headers=headers) as resp:
                    investigations = await resp.json()

            if not investigations:
                await call.message.answer(
                    "No investigations yet.\n\nTry: `/investigate github.com`",
                    parse_mode="Markdown",
                )
                return

            status_emojis = {"pending": "⏳", "running": "🔄", "completed": "✅", "failed": "❌"}
            lines = ["📜 *Your Recent Investigations*\n"]
            for inv in investigations:
                emoji = status_emojis.get(inv.get("status", ""), "❓")
                lines.append(
                    f"{emoji} *#{inv['id']}* `{inv['target']}`\n"
                    f"   {inv['target_type']} · {inv['status']} · {inv['created_at'][:10]}"
                )

            # Build quick-access keyboard for last 5
            buttons = []
            row = []
            for inv in investigations[:6]:
                e = status_emojis.get(inv.get("status", ""), "❓")
                row.append(InlineKeyboardButton(
                    text=f"{e} #{inv['id']} {inv['target'][:12]}",
                    callback_data=f"argus_status_{inv['id']}",
                ))
                if len(row) == 2:
                    buttons.append(row)
                    row = []
            if row:
                buttons.append(row)

            kb = InlineKeyboardMarkup(inline_keyboard=buttons) if buttons else None
            await call.message.answer("\n".join(lines), parse_mode="Markdown", reply_markup=kb)

        except Exception as e:
            await call.message.answer(f"❌ Error: {e}")
        return

    # ── All other actions need an inv_id ──────────────────────────────────
    if not inv_id or not inv_id.isdigit():
        await call.answer("Invalid investigation ID", show_alert=True)
        return

    # ── Status ────────────────────────────────────────────────────────────
    if action == "status":
        await call.answer("Checking status…")
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                    if resp.status == 404:
                        await call.message.answer("❌ Investigation not found.")
                        return
                    data = await resp.json()

            status = data.get("status", "unknown")
            target = data.get("target", "?")
            evidence = data.get("evidence", [])
            has_ai = any(e["plugin"] == "ai_analysis" for e in evidence)
            status_emoji = {"pending": "⏳", "running": "🔄", "completed": "✅", "failed": "❌"}.get(status, "❓")

            text = (
                f"{status_emoji} *#{inv_id}* — `{target}`\n"
                f"Status: *{status}*\n"
                f"Evidence: {len(evidence)} items"
            )

            if status == "completed":
                await call.message.answer(
                    text,
                    parse_mode="Markdown",
                    reply_markup=results_keyboard(inv_id, has_ai=has_ai),
                )
            else:
                await call.message.answer(
                    text,
                    parse_mode="Markdown",
                    reply_markup=running_keyboard(inv_id),
                )
        except Exception as e:
            await call.message.answer(f"❌ Error: {e}")
        return

    # ── Full Results ──────────────────────────────────────────────────────
    if action == "results":
        await call.answer("Loading results…")
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                    if resp.status == 404:
                        await call.message.answer("❌ Investigation not found.")
                        return
                    data = await resp.json()

            status = data.get("status")
            if status in ("running", "pending"):
                await call.message.answer(
                    f"⏳ Investigation #{inv_id} is still {status}.",
                    reply_markup=running_keyboard(inv_id),
                )
                return

            summary = data.get("summary", "")
            has_ai = any(e["plugin"] == "ai_analysis" for e in data.get("evidence", []))

            if summary:
                chunks = _chunk_text(summary, 4000)
                await call.message.answer(chunks[0], parse_mode="Markdown")
                for chunk in chunks[1:]:
                    await call.message.answer(chunk, parse_mode="Markdown")

            if has_ai:
                await call.message.answer(
                    "🤖 *AI analysis available!*",
                    parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                        InlineKeyboardButton(
                            text="🤖 Get AI Threat Report",
                            callback_data=f"argus_analyze_{inv_id}",
                        )
                    ]]),
                )
        except Exception as e:
            await call.message.answer(f"❌ Error: {e}")
        return

    # ── AI Analysis ───────────────────────────────────────────────────────
    if action == "analyze":
        await call.answer("Asking Gemini…")
        thinking = await call.message.answer(
            f"🤖 *Generating threat intelligence report for #{inv_id}…*\n_This takes a few seconds._",
            parse_mode="Markdown",
        )
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                    if resp.status == 404:
                        await thinking.edit_text("❌ Investigation not found.")
                        return
                    data = await resp.json()

            status = data.get("status")
            if status in ("running", "pending"):
                await thinking.edit_text("⏳ Investigation still running. Try again when done.")
                return

            ai_ev = next(
                (e for e in data.get("evidence", []) if e["plugin"] == "ai_analysis"), None
            )
            if ai_ev:
                report = ai_ev["data"].get("report", "")
                model = ai_ev["data"].get("model", "Gemini")
                header = f"🤖 *Gemini AI Threat Report*\n_Model: {model} · Target: {data['target']}_\n\n"
                full = header + report
                chunks = _chunk_text(full, 4000)
                await thinking.edit_text(chunks[0], parse_mode="Markdown")
                for chunk in chunks[1:]:
                    await call.message.answer(chunk, parse_mode="Markdown")
                # Offer re-run
                await call.message.answer(
                    "_Report generated from stored evidence._",
                    parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                        InlineKeyboardButton(text="🔄 Re-run AI", callback_data=f"argus_reanalyze_{inv_id}"),
                        InlineKeyboardButton(text="📋 Raw Data", callback_data=f"argus_results_{inv_id}"),
                    ]]),
                )
            else:
                # No stored AI — run live
                evidence_items = data.get("evidence", [])
                combined = {e["plugin"]: e["data"] for e in evidence_items if "error" not in e.get("data", {})}
                async with aiohttp.ClientSession() as s:
                    headers = {"Authorization": f"Bearer {token}"}
                    payload = {"target": data["target"], "evidence": combined}
                    async with s.post(
                        f"{API_BASE}/investigations/{inv_id}/analyze",
                        json=payload, headers=headers,
                    ) as resp:
                        if resp.status == 200:
                            result = await resp.json()
                            report = result.get("report", "No report generated.")
                            header = f"🤖 *Gemini AI Threat Report*\n_Target: {data['target']}_\n\n"
                            full = header + report
                            chunks = _chunk_text(full, 4000)
                            await thinking.edit_text(chunks[0], parse_mode="Markdown")
                            for chunk in chunks[1:]:
                                await call.message.answer(chunk, parse_mode="Markdown")
                        else:
                            err = await resp.text()
                            await thinking.edit_text(f"❌ Analysis failed: {err}")
        except Exception as e:
            await thinking.edit_text(f"❌ Error: {e}")
        return

    # ── Re-run AI analysis ────────────────────────────────────────────────
    if action == "reanalyze":
        await call.answer("Re-running Gemini analysis…")
        thinking = await call.message.answer(
            f"🔄 *Re-running AI analysis for #{inv_id}…*",
            parse_mode="Markdown",
        )
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                    data = await resp.json()
            evidence_items = data.get("evidence", [])
            combined = {e["plugin"]: e["data"] for e in evidence_items
                        if e["plugin"] != "ai_analysis" and "error" not in e.get("data", {})}
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                payload = {"target": data["target"], "evidence": combined}
                async with s.post(
                    f"{API_BASE}/investigations/{inv_id}/analyze",
                    json=payload, headers=headers,
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        report = result.get("report", "")
                        header = f"🤖 *Gemini AI Threat Report (refreshed)*\n_Target: {data['target']}_\n\n"
                        full = header + report
                        chunks = _chunk_text(full, 4000)
                        await thinking.edit_text(chunks[0], parse_mode="Markdown")
                        for chunk in chunks[1:]:
                            await call.message.answer(chunk, parse_mode="Markdown")
                    else:
                        await thinking.edit_text("❌ Re-analysis failed.")
        except Exception as e:
            await thinking.edit_text(f"❌ Error: {e}")
        return

    # ── Re-investigate (same target) ──────────────────────────────────────
    if action == "reinvest":
        await call.answer("Starting new investigation…")
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                async with s.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                    if resp.status == 404:
                        await call.message.answer("❌ Original investigation not found.")
                        return
                    data = await resp.json()

            target = data.get("target")
            target_type = data.get("target_type", "unknown")
            type_emoji = {
                "domain": "🌐", "url": "🔗", "ip": "🖥️", "email": "📧",
                "username": "👤", "phone": "📞", "image": "🖼️",
            }.get(target_type, "🔍")

            status_msg = await call.message.answer(
                f"{type_emoji} *Re-investigating:* `{target}`\n\n"
                f"⏳ Running fresh scan…\n_Will auto-update when done._",
                parse_mode="Markdown",
            )

            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {token}"}
                payload = {
                    "target": target,
                    "telegram_chat_id": call.message.chat.id,
                    "telegram_message_id": status_msg.message_id,
                }
                async with s.post(f"{API_BASE}/investigations", json=payload, headers=headers) as resp:
                    if resp.status in (200, 201):
                        new_data = await resp.json()
                        new_id = new_data.get("id")
                        await status_msg.edit_text(
                            f"{type_emoji} *Re-investigating:* `{target}`\n\n"
                            f"⏳ Investigation #{new_id} running…\n"
                            f"_Auto-updates when done._",
                            parse_mode="Markdown",
                            reply_markup=running_keyboard(new_id),
                        )
                    else:
                        err = await resp.text()
                        await status_msg.edit_text(f"❌ Failed: {err}")
        except Exception as e:
            await call.message.answer(f"❌ Error: {e}")
        return

    await call.answer("Unknown action", show_alert=False)
