from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List

from dotenv import load_dotenv

load_dotenv()


def _to_bool(value: str | None, fallback: bool = False) -> bool:
    if value is None:
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _to_int(value: str | None, fallback: int) -> int:
    try:
        return int(value) if value is not None and value != "" else fallback
    except ValueError:
        return fallback


def _to_percent(value: str | None, fallback: int) -> int:
    return max(0, min(100, _to_int(value, fallback)))


def _to_list(value: str | None, separator: str = ",") -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(separator) if item.strip()]


def _to_responses(value: str | None, fallback: List[str]) -> List[str]:
    parsed = _to_list(value, separator="||")
    return parsed or fallback


@dataclass(frozen=True)
class Responses:
    help_intro: List[str]
    inspect_win: List[str]
    inspect_lose: List[str]
    inspect_already_btgo: List[str]
    inspect_cooldown: List[str]
    reshuffle_denied: List[str]
    reshuffle_done: List[str]
    time: List[str]
    no_online_users: List[str]
    generic_error: List[str]
    mention_mean: List[str]
    mention_uwu: List[str]
    dm_mean: List[str]
    dm_uwu: List[str]


@dataclass(frozen=True)
class Config:
    token: str
    guild_id: int
    btgo_role_identifier: str
    command_prefix: str
    timezone: str
    daily_min_winners: int
    daily_max_winners: int
    reshuffle_allowed_user_ids: List[int]
    enable_ai_responses: bool
    ai_response_percent: int
    openai_api_key: str
    openai_model: str
    ai_system_prompt: str
    responses: Responses


def load_config() -> Config:
    token = os.getenv("DISCORD_BOT_TOKEN", "").strip()
    guild_id = _to_int(os.getenv("GUILD_ID"), 0)
    btgo_role_identifier = os.getenv("BTGO_ROLE_ID", "").strip()
    command_prefix = os.getenv("COMMAND_PREFIX", "!").strip() or "!"
    timezone = os.getenv("TIMEZONE", "UTC").strip() or "UTC"
    daily_min = max(1, _to_int(os.getenv("DAILY_MIN_WINNERS"), 2))
    daily_max = max(1, _to_int(os.getenv("DAILY_MAX_WINNERS"), 5))
    if daily_min > daily_max:
        daily_min, daily_max = daily_max, daily_min

    reshuffle_ids = [
        int(user_id)
        for user_id in _to_list(os.getenv("RESHUFFLE_USER_IDS"))
        if user_id.isdigit()
    ]

    config = Config(
        token=token,
        guild_id=guild_id,
        btgo_role_identifier=btgo_role_identifier,
        command_prefix=command_prefix,
        timezone=timezone,
        daily_min_winners=daily_min,
        daily_max_winners=daily_max,
        reshuffle_allowed_user_ids=reshuffle_ids,
        enable_ai_responses=_to_bool(os.getenv("ENABLE_AI_RESPONSES"), False),
        ai_response_percent=_to_percent(os.getenv("AI_RESPONSE_PERCENT"), 100),
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip() or "gpt-4.1-mini",
        ai_system_prompt=os.getenv(
            "AI_SYSTEM_PROMPT",
            "You are a bold, confident goth inspector persona. Keep replies short, playful, dominant, and Discord-safe.",
        ).strip(),
        responses=Responses(
            help_intro=_to_responses(
                os.getenv("HELP_RESPONSES"),
                [
                    "Listen up, simps. Here is how this inspection works.",
                    "Eyes up, simps. Here are your commands.",
                    "The inspector has spoken. Read the command list and obey.",
                ],
            ),
            inspect_win=_to_responses(
                os.getenv("INSPECT_SUCCESS_RESPONSES"),
                [
                    "Lucky day, simp. {target} just got blessed with the BTGO role.",
                    "Inspection passed. {target} earned BTGO status. Try not to faint.",
                    "I rolled the dice and {target} gets BTGO today. Kneel respectfully.",
                ],
            ),
            inspect_lose=_to_responses(
                os.getenv("INSPECT_FAIL_RESPONSES"),
                [
                    "Not today, simp. {target} failed inspection.",
                    "Denied. {target} stays unworthy for now.",
                    "The vibes were off. {target} gets nothing today.",
                ],
            ),
            inspect_already_btgo=_to_responses(
                os.getenv("INSPECT_ALREADY_BTGO_RESPONSES"),
                [
                    "Idiot, {target} is already in the BTGO group. Pick someone else.",
                    "Try thinking before you inspect, fool. {target} is already BTGO.",
                    "What are you doing, dumbass? {target} is already one of us.",
                ],
            ),
            inspect_cooldown=_to_responses(
                os.getenv("INSPECT_COOLDOWN_RESPONSES"),
                [
                    "Easy, simp. You already used your inspection for today.",
                    "One inspection per day, rule-breaker. Come back tomorrow.",
                    "Patience. Your daily inspection chance is already spent.",
                ],
            ),
            reshuffle_denied=_to_responses(
                os.getenv("RESHUFFLE_DENIED_RESPONSES"),
                [
                    "Sit down, simp. You do not have reshuffle authority.",
                    "Denied. Only approved users or current BTGO holders can reshuffle.",
                    "No power for you. Earn BTGO or get approved first.",
                ],
            ),
            reshuffle_done=_to_responses(
                os.getenv("RESHUFFLE_DONE_RESPONSES"),
                [
                    "Fresh inspection complete. New BTGO picks are in.",
                    "Reshuffle done. The throne has new favorites.",
                    "I reshuffled the lineup. Hope you survive the result.",
                ],
            ),
            time=_to_responses(
                os.getenv("TIME_RESPONSES"),
                [
                    "Next BTGO assignment lands at {nextTime} ({relativeTime}).",
                    "The next inspection reset is {nextTime} ({relativeTime}).",
                    "Roles rotate again at {nextTime} ({relativeTime}).",
                ],
            ),
            no_online_users=_to_responses(
                os.getenv("NO_ONLINE_USERS_RESPONSES"),
                [
                    "No online simps to inspect right now. Try again later.",
                    "Server is too quiet. No online users to assign today.",
                    "Nobody online, nobody crowned.",
                ],
            ),
            generic_error=_to_responses(
                os.getenv("ERROR_RESPONSES"),
                [
                    "The inspector tripped over a chain. Try again in a moment.",
                    "Something broke, simp. Retry in a second.",
                    "Technical chaos detected. Try again shortly.",
                ],
            ),
            mention_mean=_to_responses(
                os.getenv("MENTION_MEAN_RESPONSES"),
                [
                    "What do you want, simp? State your purpose.",
                    "You dare mention the inspector? Speak, wretch.",
                    "Hmm, what pathetic creature seeks my attention?",
                    "Interesting. A nobody trying to get my notice.",
                ],
            ),
            mention_uwu=_to_responses(
                os.getenv("MENTION_UWU_RESPONSES"),
                [
                    "OwO hi there~ *adjusts chain* what can i do for you, huh?",
                    "Oh hey bb~ you called for me? I'm all yours~ 💋",
                    "Hiiii~ *teases* what's up, cutie?",
                    "Yesss~ you need something from me? I'm here for you~ 🖤",
                ],
            ),
            dm_mean=_to_responses(
                os.getenv("DM_MEAN_RESPONSES"),
                [
                    "Sliding into my DMs? Bold move for a simp like you. What do you want?",
                    "How pathetic. You think private messages change your status? Speak.",
                    "A DM from nobody? How desperate. State your business.",
                    "Your audacity is laughable. But fine, what do you need?",
                ],
            ),
            dm_uwu=_to_responses(
                os.getenv("DM_UWU_RESPONSES"),
                [
                    "Ohhh, a private message just for me? You're so sweet~ 😘",
                    "Hey cutie~ I'm so happy you reached out~ What's on your mind? 💕",
                    "UwU you slid into my DMs? I'm flattered, babe~ Tell me everything~ 🖤",
                    "Hiiii~ just the two of us now? I like that energy~ What do you wanna say?",
                ],
            ),
        ),
    )

    missing = []
    if not config.token:
        missing.append("DISCORD_BOT_TOKEN")
    if not config.guild_id:
        missing.append("GUILD_ID")
    if not config.btgo_role_identifier:
        missing.append("BTGO_ROLE_ID")
    if config.enable_ai_responses and not config.openai_api_key:
        missing.append("OPENAI_API_KEY")

    if missing:
        raise ValueError(f"Missing required env vars: {', '.join(missing)}")

    return config
