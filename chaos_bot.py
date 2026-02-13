"""
Discord "random reply" bot with:
- Per-channel message counting
- Random trigger between MIN_MESSAGES and MAX_MESSAGES
- Random canned responses
- Optional ChatGPT "fact check" reply

Install:
  sudo apt install python3-dev pip python3-venv
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -U discord.py openai
  python3 ./chaos_bot.py
  deactivate

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

# Conversation context size (last N messages BEFORE the triggering message)
CONTEXT_MESSAGE_COUNT = 10

# -----------------------------
# PROMPT STRUCTURE (3 LAYERS)
# -----------------------------
# 1) AI_SYSTEM_PROMPT:
#    "Who the assistant is" + global behavior rules. This stays mostly constant across calls.
AI_SYSTEM_PROMPT = (
    "You are a witty, slightly sarcastic fact-checking assistant for a Discord server. "
    "Keep replies short (1-3 sentences), playful, and avoid harassment. "
    "If what was said makes no sense just spout utterly ridiculous nonsense. "
    "If someone is making a point, argue the opposing side and post something that counters that point. "
)

# 2) AI_TASK_INSTRUCTION:
#    "What to do right now" for this specific completion. Easy to tweak without changing personality.
AI_TASK_INSTRUCTION = (
    "Fact-check the latest message in a playful way. "
    "If it's a claim, point out what would need evidence or what could be wrong."
    "Do not explicitly state Counterpoint or Opinion/Joke. Let that be implied. Communicate as human would in a conversation."
)

# 3) AI_CONTEXT_TEMPLATE:
#    "How inputs are formatted" (chat history + latest message). Pure formatting; no style rules here.
AI_CONTEXT_TEMPLATE = (
    "Recent conversation (most recent last):\n"
    "{context}\n\n"
    "Latest message to respond to:\n"
    "{author}: {latest}\n"
)

# Safety / limits
IGNORE_BOTS = True
MAX_MESSAGE_CHARS_TO_FACTCHECK = 500  # skip AI if message is too long
MAX_CONTEXT_CHARS = 2500              # truncate context to control token/cost
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


def has_openai_key() -> bool:
    return bool(OPENAI_API_KEY) and OPENAI_API_KEY != "PUT_YOUR_OPENAI_API_KEY_HERE"


def _truncate_keep_end(text: str, max_chars: int) -> str:
    """Keep only the last max_chars characters to control token usage/cost."""
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


async def ai_fact_check(trigger_message: discord.Message) -> str:
    """
    Uses OpenAI to produce a short 'fact-check' style reply,
    using the last CONTEXT_MESSAGE_COUNT messages as context.
    """
    # Build context from the last N messages before the triggering message
    lines = []
    async for msg in trigger_message.channel.history(limit=CONTEXT_MESSAGE_COUNT, before=trigger_message):
        if IGNORE_BOTS and msg.author.bot:
            continue

        content = (msg.content or "").strip()
        if not content:
            continue

        lines.append(f"{msg.author.display_name}: {content}")

    lines.reverse()  # oldest -> newest
    context_text = _truncate_keep_end("\n".join(lines), MAX_CONTEXT_CHARS)

    # Fill your context template dynamically
    user_prompt = AI_CONTEXT_TEMPLATE.format(
        context=context_text if context_text else "(no prior messages)",
        author=trigger_message.author.display_name,
        latest=(trigger_message.content or "").strip(),
    )

    # Combine task instruction + formatted context into the user message
    full_user_message = f"{AI_TASK_INSTRUCTION}\n\n{user_prompt}"

    resp = await openai_client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": full_user_message},
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

    if state["count"] < state["target"]:
        return

    # Trigger hit — decide reply type
    reply_text = None
    triggering_text = (message.content or "").strip()

    use_ai = (
        ENABLE_AI_FACT_CHECK
        and has_openai_key()
        and random.random() < AI_RESPONSE_CHANCE
        and triggering_text
        and len(triggering_text) <= MAX_MESSAGE_CHARS_TO_FACTCHECK
    )

    if use_ai:
        try:
            # NOTE: pass the Message object so we can fetch the last N messages for context
            reply_text = await ai_fact_check(message)
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
