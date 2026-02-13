"""
Discord "random reply" bot with:
- Per-channel message counting
- Random trigger between MIN_MESSAGES and MAX_MESSAGES
- Random canned responses
- Optional ChatGPT "fact check" reply

Install:
  pip install -U discord.py openai

Discord Developer Portal:
- Enable "Message Content Intent" for your bot
"""

import asyncio
import os
import random
import discord
from openai import AsyncOpenAI


# =========================
# CONFIG (ALL VARIABLES HERE)
# =========================

# --- Tokens (recommended: set env vars instead of hardcoding) ---
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "PUT_YOUR_DISCORD_BOT_TOKEN_HERE")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "PUT_YOUR_OPENAI_API_KEY_HERE")

# --- Channel targeting ---
# Put ONE channel ID here, OR use ALLOWED_CHANNEL_IDS list below.
CHANNEL_ID = 123456789012345678  # <- replace with your channel ID (right-click channel -> Copy ID)

# If you want multiple channels, set this list and set CHANNEL_ID = 0
ALLOWED_CHANNEL_IDS = []  # e.g. [111111111111111111, 222222222222222222]

# --- Random trigger window ---
MIN_MESSAGES = 1
MAX_MESSAGES = 100

# --- Responses ---
CANNED_RESPONSES = [
    "You are being a douche.",
    "citation needed 🧾",
    "source: trust me bro",
    "this claim is under investigation 🔎",
    "fact check: vibes are questionable",
]

PRESENCE_OPTIONS = [
    "Im watching you",
    "Counting your messages",
    "I know what you are thinking",
    "Really into voyeurism",
    "Nothing is beyond our reach"
]

# --- AI behavior ---
ENABLE_AI_FACT_CHECK = True
OPENAI_MODEL = "gpt-4o-mini"

# When the trigger hits, choose AI vs canned:
AI_RESPONSE_CHANCE = 0.60  # 0.0 = never AI, 1.0 = always AI (if ENABLE_AI_FACT_CHECK True)

# AI style / tone
AI_SYSTEM_PROMPT = (
    "You are a witty, slightly sarcastic fact-checking assistant for a Discord server. "
    "Keep replies short (1-3 sentences), playful, and avoid harassment. "
    "If what was said makes no sense just spout utterly ridiculous nonsense"
    "If someone is making a point, research the opposing side and post something that counters that point"
)

# Safety / limits
IGNORE_BOTS = True
MAX_MESSAGE_CHARS_TO_FACTCHECK = 500  # skip AI if message is too long
COOLDOWN_SECONDS_AFTER_REPLY = 0.0    # optional cooldown after the bot replies (0 = none)

# =========================
# END CONFIG
# =========================


# Intents required for reading message content
intents = discord.Intents.default()
intents.message_content = True

discord_client = discord.Client(intents=intents)

# OpenAI client (async)
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# Per-channel counters/targets so multiple channels work independently
channel_state = {}  # channel_id -> {"count": int, "target": int}


def is_allowed_channel(channel_id: int) -> bool:
    if ALLOWED_CHANNEL_IDS:
        return channel_id in ALLOWED_CHANNEL_IDS
    return channel_id == CHANNEL_ID


def get_or_init_state(channel_id: int):
    if channel_id not in channel_state:
        channel_state[channel_id] = {
            "count": 0,
            "target": random.randint(MIN_MESSAGES, MAX_MESSAGES),
        }
    return channel_state[channel_id]


async def ai_fact_check(message_text: str) -> str:
    """
    Uses OpenAI to produce a short 'fact-check' style reply.
    """
    resp = await openai_client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": f"Fact-check this message (playful): {message_text}"},
        ],
    )
    return resp.choices[0].message.content.strip()


@discord_client.event
async def on_ready():
    await discord_client.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=random.choice(PRESENCE_OPTIONS)
        )
    )

    print(f"Logged in as {discord_client.user} (id={discord_client.user.id})")

    if ALLOWED_CHANNEL_IDS:
        print(f"Watching channels: {ALLOWED_CHANNEL_IDS}")
    else:
        print(f"Watching channel: {CHANNEL_ID}")

    print(f"Trigger range: {MIN_MESSAGES}..{MAX_MESSAGES}")

@discord_client.event
async def on_message(message: discord.Message):
    # Ignore ourselves
    if message.author == discord_client.user:
        return

    # Optional: ignore other bots
    if IGNORE_BOTS and message.author.bot:
        return

    # Channel filter
    if not is_allowed_channel(message.channel.id):
        return

    state = get_or_init_state(message.channel.id)
    state["count"] += 1

    # Debug:
    # print(f"[{message.channel.id}] {state['count']}/{state['target']}")

    if state["count"] < state["target"]:
        return

    # Trigger hit — decide reply type
    reply_text = None

    use_ai = (
        ENABLE_AI_FACT_CHECK
        and OPENAI_API_KEY
        and OPENAI_API_KEY != "PUT_YOUR_OPENAI_API_KEY_HERE"
        and random.random() < AI_RESPONSE_CHANCE
        and message.content
        and len(message.content) <= MAX_MESSAGE_CHARS_TO_FACTCHECK
    )

    if use_ai:
        try:
            reply_text = await ai_fact_check(message.content)
        except Exception as e:
            # Fallback if OpenAI fails
            reply_text = random.choice(CANNED_RESPONSES)
            print(f"OpenAI error: {e!r}")
    else:
        reply_text = random.choice(CANNED_RESPONSES)

    # Reply to the triggering message
    try:
        await message.reply(reply_text)
    except Exception as e:
        print(f"Discord reply error: {e!r}")

    # Reset counter + choose new random target
    state["count"] = 0
    state["target"] = random.randint(MIN_MESSAGES, MAX_MESSAGES)

    # Optional cooldown
    if COOLDOWN_SECONDS_AFTER_REPLY > 0:
        await asyncio.sleep(COOLDOWN_SECONDS_AFTER_REPLY)


if __name__ == "__main__":
    if not DISCORD_BOT_TOKEN or DISCORD_BOT_TOKEN == "PUT_YOUR_DISCORD_BOT_TOKEN_HERE":
        raise RuntimeError("Missing DISCORD_BOT_TOKEN. Set env var or edit DISCORD_BOT_TOKEN in the script.")

    # If user set multiple channels, allow CHANNEL_ID to be left as placeholder (0/whatever)
    if not ALLOWED_CHANNEL_IDS and (not CHANNEL_ID or CHANNEL_ID == 123456789012345678):
        print("Heads up: CHANNEL_ID still looks like a placeholder. Set it to your real channel ID.")

    discord_client.run(DISCORD_BOT_TOKEN)
