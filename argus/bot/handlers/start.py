from aiogram import Router, F
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton
from aiogram.filters import CommandStart, Command
import aiohttp
from config import get_settings

router = Router()
settings = get_settings()
API_BASE = f"http://localhost:{settings.api_port}/api/v1"


async def get_or_create_token(message: Message) -> str | None:
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "telegram_id": message.from_user.id,
                "username": message.from_user.username,
                "full_name": message.from_user.full_name,
            }
            async with session.post(f"{API_BASE}/users/auth/telegram", json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("access_token")
    except Exception:
        pass
    return None


@router.message(CommandStart())
async def cmd_start(message: Message):
    token = await get_or_create_token(message)
    name = message.from_user.first_name or "there"

    if token:
        text = (
            f"👁 *Welcome to Argus OSINT, {name}!*\n\n"
            "I'm your AI-powered open-source intelligence platform. "
            "Give me any target and I'll run a full OSINT scan, then Gemini AI writes a threat intelligence report.\n\n"
            "*🎯 What I can investigate:*\n"
            "🌐 `github.com` — Domain\n"
            "🔗 `https://example.com` — URL\n"
            "🖥️ `8.8.8.8` — IP Address\n"
            "📧 `user@gmail.com` — Email address\n"
            "👤 `@username` — Username (50+ platforms)\n"
            "📞 `+14155552671` — Phone number\n"
            "🖼️ `https://site.com/photo.jpg` — Image EXIF\n"
            "🧑 `John Smith` — Person name\n"
            "🏢 `Acme Corp` — Company name\n\n"
            "*⚡ Commands:*\n"
            "/investigate `<target>` — start OSINT scan\n"
            "/analyze `<id>` — 🤖 Gemini AI threat report\n"
            "/results `<id>` — raw evidence data\n"
            "/status `<id>` — check progress\n"
            "/history — your recent investigations\n"
            "/help — show this menu\n\n"
            "🔍 *Try now:* `/investigate @elonmusk`"
        )
    else:
        text = (
            f"👁 Welcome to Argus OSINT, {name}!\n\n"
            "⚠️ Could not connect to the API. Please try again in a moment."
        )

    # Task 9: Quick-Reply Keyboard
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🌐 Domain"), KeyboardButton(text="🔗 URL"), KeyboardButton(text="🖥️ IP")],
            [KeyboardButton(text="📧 Email"), KeyboardButton(text="👤 Username"), KeyboardButton(text="📞 Phone")],
        ],
        resize_keyboard=True,
        one_time_keyboard=False,
    )
    await message.answer(text, parse_mode="Markdown", reply_markup=keyboard)


# Task 9: Handle quick-reply button presses
TARGET_TYPE_PROMPTS = {
    "🌐 Domain": ("🌐", "domain", "Send me a domain to investigate.\n\n*Example:* `github.com`\n*Example:* `example.org`"),
    "🔗 URL": ("🔗", "url", "Send me a URL to investigate.\n\n*Example:* `https://example.com/page`"),
    "🖥️ IP": ("🖥️", "ip", "Send me an IP address to investigate.\n\n*Example:* `8.8.8.8`"),
    "📧 Email": ("📧", "email", "Send me an email address to investigate.\n\n*Example:* `user@gmail.com`"),
    "👤 Username": ("👤", "username", "Send me a username to investigate.\n\n*Example:* `@elonmusk`\n*Example:* `username`"),
    "📞 Phone": ("📞", "phone", "Send me a phone number to investigate.\n\n*Example:* `+14155552671`"),
}


@router.message(F.text.in_(TARGET_TYPE_PROMPTS))
async def handle_quick_reply(message: Message):
    prompt = TARGET_TYPE_PROMPTS[message.text]
    emoji, target_type, text = prompt
    await message.answer(text, parse_mode="Markdown")


@router.message(Command("help"))
async def cmd_help(message: Message):
    text = (
        "👁 *Argus OSINT — Help*\n\n"
        "*🎯 Investigation targets:*\n"
        "• `example.com` — Domain investigation\n"
        "• `https://example.com` — URL investigation\n"
        "• `192.168.1.1` — IP address lookup\n"
        "• `user@gmail.com` — Email OSINT\n"
        "• `@username` or `username` — Username hunt\n"
        "• `+14155552671` — Phone number lookup\n"
        "• Image URL ending in .jpg/.png — EXIF forensics\n"
        "• `John Smith` — Person name intelligence\n"
        "• `Acme Corp` — Company name intelligence\n\n"
        "*⚡ Commands:*\n"
        "`/investigate <target>` — Run full OSINT scan\n"
        "`/analyze <id>` — 🤖 Gemini AI threat report\n"
        "`/results <id>` — View raw evidence\n"
        "`/status <id>` — Check investigation status\n"
        "`/history` — Your last 10 investigations\n\n"
        "*🔌 Plugins by target type:*\n"
        "🌐 Domain/URL: WHOIS · DNS · Certs · IP Geo · HTTP · Shodan · BGP · Subdomains · Wayback · Reputation · Passive DNS · Pastes · GitHub\n"
        "📧 Email: Reputation · Breach DB · Social accounts · Gravatar · MX check · GitHub\n"
        "👤 Username: 50+ platforms + Profile deep dive (GitHub, Reddit, HN, X)\n"
        "📞 Phone: Carrier · Country · Line type · Timezone · Risk flags\n"
        "🖼️ Image: EXIF · GPS · Camera · Reverse search links\n"
        "🧑 Person: News · Companies · SEC filings · LinkedIn · Web search\n"
        "🏢 Company: OpenCorporates · News · SEC EDGAR · LinkedIn\n\n"
        "*🤖 AI Analysis:*\n"
        "After every investigation, Gemini reads all the evidence and writes a professional threat intelligence report with risk assessment.\n\n"
        "_All data comes from free public sources. No paid APIs required._"
    )
    await message.answer(text, parse_mode="Markdown")
