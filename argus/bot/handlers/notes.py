"""
Investigation notes bot command — /note <id> <text>
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


@router.message(Command("note"))
async def cmd_note(message: Message):
    args = message.text.split(maxsplit=2)
    if len(args) < 3 or not args[1].strip().isdigit() or not args[2].strip():
        await message.answer(
            "❌ Please provide an investigation ID and note text.\n\n"
            "*Usage:*\n"
            "`/note <id> <your note text>`\n\n"
            "*Example:*\n"
            "`/note 42 Suspicious domain — follow up with admin`",
            parse_mode="Markdown",
        )
        return

    inv_id = args[1].strip()
    content = args[2].strip()

    token = await get_or_create_token(message)
    if not token:
        await message.answer("❌ Authentication failed. Please send /start and try again.")
        return

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            payload = {"content": content}
            async with session.post(
                f"{API_BASE}/investigations/{inv_id}/notes",
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status == 404:
                    await message.answer("❌ Investigation not found.")
                    return
                if resp.status not in (200, 201):
                    err = await resp.text()
                    await message.answer(f"❌ Failed to add note: {err}")
                    return
                data = await resp.json()

        note_id = data.get("id")
        await message.answer(
            f"📝 *Note added to investigation #{inv_id}*\n\n"
            f"Note #{note_id}: {content[:200]}",
            parse_mode="Markdown",
        )
    except Exception as e:
        await message.answer(f"❌ Error: {e}")