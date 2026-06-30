"""
Bulk investigation bot command — /bulk <targets separated by commas or newlines>
"""
import aiohttp
from aiogram import Router
from aiogram.types import Message
from aiogram.filters import Command
from config import get_settings
from bot.handlers.start import get_or_create_token

router = Router()
settings = get_settings()
API_BASE = f"http://localhost:{settings.api_port}/api/v1"


@router.message(Command("bulk"))
async def cmd_bulk(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip():
        await message.answer(
            "❌ Please provide targets.\n\n"
            "*Usage:*\n"
            "`/bulk target1, target2, target3`\n"
            "`/bulk target1\\ntarget2\\ntarget3`\n\n"
            "Maximum 50 targets per request.",
            parse_mode="Markdown",
        )
        return

    raw = args[1].strip()
    # Split by commas or newlines
    targets = [t.strip() for t in raw.replace("\n", ",").split(",") if t.strip()]

    if not targets:
        await message.answer("❌ No valid targets found.")
        return
    if len(targets) > 50:
        await message.answer(f"❌ Too many targets ({len(targets)}). Maximum is 50.")
        return

    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Authentication failed. Please send /start and try again.")
        return

    status_msg = await message.answer(
        f"📦 *Starting {len(targets)} investigations…*\n\n"
        f"Targets:\n" + "\n".join(f"• `{t}`" for t in targets[:10])
        + (f"\n… and {len(targets) - 10} more" if len(targets) > 10 else ""),
        parse_mode="Markdown",
    )

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            payload = {"targets": targets}
            async with session.post(
                f"{API_BASE}/investigations/bulk",
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status not in (200, 201):
                    err = await resp.text()
                    await status_msg.edit_text(f"❌ Bulk investigation failed: {err}")
                    return
                data = await resp.json()

        ids = data.get("investigations", [])
        count = data.get("count", 0)
        await status_msg.edit_text(
            f"✅ *{count} investigations started!*\n\n"
            + "\n".join(f"  • #{i} `{targets[idx]}`" for idx, i in enumerate(ids[:15]))
            + (f"\n  … and {count - 15} more" if count > 15 else "")
            + "\n\n_Results will appear when each completes._",
            parse_mode="Markdown",
        )
    except Exception as e:
        await status_msg.edit_text(f"❌ Error: {e}")