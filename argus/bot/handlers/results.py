from aiogram import Router
from aiogram.types import Message
from aiogram.filters import Command
import aiohttp
from config import get_settings
from bot.handlers.start import get_or_create_token

router = Router()
settings = get_settings()
API_BASE = f"http://localhost:{settings.api_port}/api/v1"


@router.message(Command("results"))
async def cmd_results(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.answer(
            "❌ Please provide an investigation ID.\n\n*Usage:* `/results <id>`",
            parse_mode="Markdown",
        )
        return

    inv_id = args[1].strip()
    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Authentication failed. Please send /start.")
        return

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                if resp.status == 404:
                    await message.answer("❌ Investigation not found.")
                    return
                data = await resp.json()

        status = data.get("status")
        if status == "running":
            await message.answer(f"⏳ Investigation #{inv_id} is still running. Check back soon!")
            return
        if status == "pending":
            await message.answer(f"⏳ Investigation #{inv_id} hasn't started yet.")
            return

        summary = data.get("summary")
        has_ai = any(e["plugin"] == "ai_analysis" for e in data.get("evidence", []))

        if summary:
            chunks = _chunk_text(summary, 4000)
            for chunk in chunks:
                await message.answer(chunk, parse_mode="Markdown")
        else:
            await message.answer(f"Investigation #{inv_id} completed but no data was collected.")

        if has_ai:
            await message.answer(
                f"🤖 *AI analysis available!*\nRun `/analyze {inv_id}` for Gemini's threat intelligence report.",
                parse_mode="Markdown",
            )

    except Exception as e:
        await message.answer(f"❌ Error fetching results: {e}")


@router.message(Command("analyze"))
async def cmd_analyze(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.answer(
            "❌ Please provide an investigation ID.\n\n*Usage:* `/analyze <id>`",
            parse_mode="Markdown",
        )
        return

    inv_id = args[1].strip()
    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Authentication failed. Please send /start.")
        return

    thinking_msg = await message.answer(
        f"🤖 *Asking Gemini to analyze investigation #{inv_id}…*\n\n_Synthesizing OSINT evidence into a threat intelligence report…_",
        parse_mode="Markdown",
    )

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{API_BASE}/investigations/{inv_id}", headers=headers) as resp:
                if resp.status == 404:
                    await thinking_msg.edit_text("❌ Investigation not found.")
                    return
                data = await resp.json()

        status = data.get("status")
        if status in ("running", "pending"):
            await thinking_msg.edit_text("⏳ Investigation is still running. Try again when it's done.")
            return

        # Find stored AI analysis
        ai_evidence = next(
            (e for e in data.get("evidence", []) if e["plugin"] == "ai_analysis"), None
        )

        if ai_evidence:
            report = ai_evidence["data"].get("report", "")
            model = ai_evidence["data"].get("model", "Gemini")
            header = f"🤖 *Gemini AI Threat Intelligence Report*\n_Model: {model} | Target: {data['target']}_\n\n"
            full = header + report
            chunks = _chunk_text(full, 4000)
            await thinking_msg.edit_text(chunks[0], parse_mode="Markdown")
            for chunk in chunks[1:]:
                await message.answer(chunk, parse_mode="Markdown")
        else:
            # No stored analysis — run it live
            evidence_items = data.get("evidence", [])
            if not evidence_items:
                await thinking_msg.edit_text("❌ No evidence collected yet for this investigation.")
                return

            combined = {e["plugin"]: e["data"] for e in evidence_items if "error" not in e.get("data", {})}
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {token}"}
                payload = {"target": data["target"], "evidence": combined}
                async with session.post(f"{API_BASE}/investigations/{inv_id}/analyze", json=payload, headers=headers) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        report = result.get("report", "No report generated.")
                        header = f"🤖 *Gemini AI Threat Intelligence Report*\n_Target: {data['target']}_\n\n"
                        full = header + report
                        chunks = _chunk_text(full, 4000)
                        await thinking_msg.edit_text(chunks[0], parse_mode="Markdown")
                        for chunk in chunks[1:]:
                            await message.answer(chunk, parse_mode="Markdown")
                    else:
                        err = await resp.text()
                        await thinking_msg.edit_text(f"❌ Analysis failed: {err}")

    except Exception as e:
        await thinking_msg.edit_text(f"❌ Error: {e}")


@router.message(Command("history"))
async def cmd_history(message: Message):
    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Authentication failed. Please send /start.")
        return

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{API_BASE}/investigations?limit=10", headers=headers) as resp:
                investigations = await resp.json()

        if not investigations:
            await message.answer("You haven't run any investigations yet.\n\nTry: `/investigate github.com`", parse_mode="Markdown")
            return

        lines = ["📋 *Your Recent Investigations*\n"]
        status_emojis = {"pending": "⏳", "running": "🔄", "completed": "✅", "failed": "❌"}

        for inv in investigations:
            emoji = status_emojis.get(inv.get("status", ""), "❓")
            lines.append(
                f"{emoji} *#{inv['id']}* `{inv['target']}`\n"
                f"   Type: {inv['target_type']} | {inv['status']}\n"
                f"   {inv['created_at'][:10]}"
            )

        lines.append("\n_Use /results\\_<id> · /analyze\\_<id> for details_")
        await message.answer("\n".join(lines), parse_mode="Markdown")

    except Exception as e:
        await message.answer(f"❌ Error fetching history: {e}")


def _chunk_text(text: str, max_len: int) -> list[str]:
    if len(text) <= max_len:
        return [text]
    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks
