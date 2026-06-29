from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Optional
from zoneinfo import ZoneInfo

import discord
from discord.ext import commands
from openai import AsyncOpenAI, BadRequestError

from config_parse import Config, load_config

DATA_DIR = Path("data")
STATE_PATH = DATA_DIR / "state.json"
APP_DIR = Path(__file__).resolve().parent
BOT_LOG_PATH_ENV = os.getenv("BOT_LOG_PATH", "data/bot.log").strip() or "data/bot.log"
BOT_LOG_PATH = Path(BOT_LOG_PATH_ENV)
if not BOT_LOG_PATH.is_absolute():
    BOT_LOG_PATH = (APP_DIR / BOT_LOG_PATH).resolve()

DATA_DIR.mkdir(parents=True, exist_ok=True)
BOT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BOT_LOG_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("btgo")
FALLBACK_OPENAI_MODEL = "gpt-5-mini"


@contextlib.asynccontextmanager
async def maybe_typing(destination: discord.abc.Messageable) -> AsyncIterator[None]:
    """Show typing indicator where supported while we wait on slower operations."""
    typing_factory = getattr(destination, "typing", None)
    if callable(typing_factory):
        async with typing_factory():
            yield
        return
    yield


def load_state() -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_PATH.exists():
        logger.info("State file did not exist; starting with default state.")
        return {
            "btgo_role_member_ids": [],
            "inspect_usage_by_user_date": {},
            "last_daily_shuffle_date": "",
        }

    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.exception("State file could not be decoded; falling back to default state.")
        return {
            "btgo_role_member_ids": [],
            "inspect_usage_by_user_date": {},
            "last_daily_shuffle_date": "",
        }


def save_state(state: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def format_with_vars(template: str, values: dict[str, Any]) -> str:
    result = template
    for key, value in values.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


class BtgoBot(commands.Bot):
    def __init__(self, config: Config) -> None:
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        intents.presences = True
        intents.messages = True
        intents.message_content = True

        super().__init__(command_prefix=config.command_prefix, intents=intents, help_command=None)
        self.config = config
        self.state = load_state()
        self.timezone = ZoneInfo(config.timezone)
        self.openai_model = config.openai_model
        self.openai_client = (
            AsyncOpenAI(
                api_key=config.openai_api_key,
                timeout=config.openai_timeout_seconds,
            )
            if config.enable_ai_responses and config.openai_api_key
            else None
        )
        self.daily_task: Optional[asyncio.Task[None]] = None
        self.ibtc_taunt_task: Optional[asyncio.Task[None]] = None

    @staticmethod
    def is_model_not_found_error(error: Exception) -> bool:
        if isinstance(error, BadRequestError) and getattr(error, "code", None) == "model_not_found":
            return True
        message = str(error).lower()
        return "model_not_found" in message or ("model" in message and "does not exist" in message)

    async def create_ai_response(self, context_name: str, prompt_input: list[dict[str, str]]) -> Any:
        if self.openai_client is None:
            raise RuntimeError("OpenAI client is unavailable")

        try:
            return await self.openai_client.responses.create(model=self.openai_model, input=prompt_input)
        except Exception as error:
            if self.is_model_not_found_error(error) and self.openai_model != FALLBACK_OPENAI_MODEL:
                previous_model = self.openai_model
                self.openai_model = FALLBACK_OPENAI_MODEL
                logger.warning(
                    "Configured model '%s' was not found for context=%s; retrying with fallback model '%s'.",
                    previous_model,
                    context_name,
                    self.openai_model,
                )
                return await self.openai_client.responses.create(model=self.openai_model, input=prompt_input)
            raise

    async def setup_hook(self) -> None:
        logger.info("Starting daily shuffle background task.")
        self.daily_task = asyncio.create_task(self.daily_shuffle_loop())
        logger.info("Starting IBTC taunt background task.")
        self.ibtc_taunt_task = asyncio.create_task(self.ibtc_taunt_loop())

    async def close(self) -> None:
        if self.daily_task:
            self.daily_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.daily_task
        if self.ibtc_taunt_task:
            self.ibtc_taunt_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.ibtc_taunt_task
        await super().close()

    def current_date_key(self) -> str:
        return datetime.now(self.timezone).strftime("%Y-%m-%d")

    def next_midnight(self) -> datetime:
        now = datetime.now(self.timezone)
        tomorrow = (now + timedelta(days=1)).date()
        return datetime.combine(tomorrow, datetime.min.time(), tzinfo=self.timezone)

    def should_use_ai(self) -> bool:
        if not self.openai_client:
            return False
        return random.uniform(0, 100) < self.config.ai_response_percent

    def pick_response(self, options: list[str]) -> str:
        return random.choice(options)

    async def build_character_response(
        self,
        context_name: str,
        response_pool: list[str],
        values: Optional[dict[str, Any]] = None,
    ) -> str:
        values = values or {}
        start_time = asyncio.get_running_loop().time()
        fallback = format_with_vars(self.pick_response(response_pool), values)

        if not self.should_use_ai():
            logger.info(
                "AI skipped for context=%s (enabled=%s percent=%s); using fallback.",
                context_name,
                bool(self.openai_client),
                self.config.ai_response_percent,
            )
            return fallback

        try:
            openai_client = self.openai_client
            if openai_client is None:
                logger.warning("AI selected for context=%s but OpenAI client is unavailable.", context_name)
                return fallback

            variable_lines = "\n".join(f"{key}: {value}" for key, value in values.items())
            prompt = [
                f"Write one short Discord message for context: {context_name}.",
                "Stay in persona and keep it concise.",
                "Do not include markdown.",
            ]
            if variable_lines:
                prompt.append(f"Variables:\n{variable_lines}")

            if self.config.log_ai_payload:
                logger.info("AI request context=%s prompt=%s", context_name, " | ".join(prompt))

            completion = await self.create_ai_response(
                context_name,
                [
                    {"role": "system", "content": self.config.ai_system_prompt},
                    {"role": "user", "content": "\n".join(prompt)},
                ],
            )
            output = (completion.output_text or "").strip()
            elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            if output:
                logger.info(
                    "AI response success context=%s model=%s elapsed_ms=%.0f response_chars=%s",
                    context_name,
                    self.openai_model,
                    elapsed_ms,
                    len(output),
                )
                return output

            logger.warning(
                "AI response empty context=%s model=%s elapsed_ms=%.0f; using fallback.",
                context_name,
                self.openai_model,
                elapsed_ms,
            )
            return fallback
        except Exception:
            elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            logger.exception(
                "AI response failed context=%s model=%s elapsed_ms=%.0f; using fallback.",
                context_name,
                self.openai_model,
                elapsed_ms,
            )
            return fallback

    async def send_character_message(
        self,
        destination: discord.abc.Messageable,
        context_name: str,
        response_pool: list[str],
        values: Optional[dict[str, Any]] = None,
    ) -> discord.Message:
        start_time = asyncio.get_running_loop().time()
        async with maybe_typing(destination):
            content = await self.build_character_response(context_name, response_pool, values)
            sent = await destination.send(content)
        elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        logger.info(
            "Message sent context=%s elapsed_ms=%.0f chars=%s",
            context_name,
            elapsed_ms,
            len(content),
        )
        return sent

    async def fetch_target_guild(self) -> discord.Guild:
        guild = self.get_guild(self.config.guild_id)
        if guild is None:
            logger.info("Guild %s was not cached; fetching from API.", self.config.guild_id)
            guild = await self.fetch_guild(self.config.guild_id)
        if not isinstance(guild, discord.Guild):
            raise RuntimeError("Configured guild could not be loaded.")
        await guild.chunk(cache=True)
        return guild

    def resolve_configured_role(self, guild: discord.Guild, identifier: str, label: str) -> discord.Role:
        role = None
        if identifier.isdigit():
            role = guild.get_role(int(identifier))
        if role is None:
            role = discord.utils.get(guild.roles, name=identifier)
        if role is None:
            raise RuntimeError(f"Configured {label} role was not found.")
        return role

    def resolve_btgo_role(self, guild: discord.Guild) -> discord.Role:
        return self.resolve_configured_role(guild, self.config.btgo_role_identifier, "BTGO")

    def resolve_ibtc_role(self, guild: discord.Guild) -> discord.Role:
        return self.resolve_configured_role(guild, self.config.ibtc_role_identifier, "IBTC")

    def is_never_pass_user(self, user_id: int) -> bool:
        return user_id in self.config.never_pass_user_ids

    def is_always_pass_user(self, user_id: int) -> bool:
        return user_id in self.config.always_pass_user_ids

    async def clear_btgo_roles(self, guild: discord.Guild, role: discord.Role) -> None:
        logger.info("Clearing BTGO role from %s current holders.", len(role.members))
        for member in list(role.members):
            await member.remove_roles(role, reason="Daily BTGO reset")
        self.state["btgo_role_member_ids"] = []
        save_state(self.state)

    async def clear_ibtc_roles(self, role: discord.Role, reason: str = "Daily IBTC reset") -> int:
        cleared_count = len(role.members)
        logger.info("Clearing IBTC role from %s current holders. reason=%s", cleared_count, reason)
        for member in list(role.members):
            await member.remove_roles(role, reason=reason)
        return cleared_count

    async def enforce_ibtc_precedence(self, guild: discord.Guild, member: discord.Member, reason: str) -> bool:
        btgo_role = self.resolve_btgo_role(guild)
        ibtc_role = self.resolve_ibtc_role(guild)
        if btgo_role not in member.roles or ibtc_role not in member.roles:
            return False

        await member.remove_roles(btgo_role, reason=reason)
        tracked = set(self.state.get("btgo_role_member_ids", []))
        if member.id in tracked:
            tracked.remove(member.id)
            self.state["btgo_role_member_ids"] = list(tracked)
            save_state(self.state)

        logger.info(
            "Enforced IBTC precedence for %s (%s): removed BTGO role.",
            member.display_name,
            member.id,
        )
        return True

    async def assign_ibtc_role_to_member(self, guild: discord.Guild, member: discord.Member, reason: str) -> None:
        role = self.resolve_ibtc_role(guild)
        if role not in member.roles:
            await member.add_roles(role, reason=reason)
            logger.info("Assigned IBTC role to %s for reason '%s'.", member.display_name, reason)

        await self.enforce_ibtc_precedence(guild, member, reason="IBTC precedence after IBTC assignment")

    async def get_online_humans(self, guild: discord.Guild) -> list[discord.Member]:
        members = []
        for member in guild.members:
            if member.bot:
                continue
            status = getattr(member, "status", discord.Status.offline)
            if status == discord.Status.offline:
                continue
            members.append(member)
        logger.info("Found %s online human members eligible for selection.", len(members))
        return members

    def get_daily_winner_count(self, online_count: int) -> int:
        minimum = max(1, min(self.config.daily_min_winners, online_count))
        maximum = max(minimum, min(self.config.daily_max_winners, online_count))
        return random.randint(minimum, maximum)

    def choose_daily_winners(self, online_members: list[discord.Member]) -> list[discord.Member]:
        eligible = [member for member in online_members if not self.is_never_pass_user(member.id)]
        if not eligible:
            return []

        always_pass_members = [member for member in eligible if self.is_always_pass_user(member.id)]
        remaining_members = [member for member in eligible if member.id not in {m.id for m in always_pass_members}]

        if not remaining_members:
            return always_pass_members

        random_count = self.get_daily_winner_count(len(remaining_members))
        random_winners = random.sample(remaining_members, random_count)

        winners_by_id: dict[int, discord.Member] = {member.id: member for member in always_pass_members}
        for member in random_winners:
            winners_by_id[member.id] = member
        return list(winners_by_id.values())

    async def apply_btgo_to_members(
        self,
        role: discord.Role,
        members: Iterable[discord.Member],
        reason: str,
    ) -> None:
        tracked = set(self.state.get("btgo_role_member_ids", []))
        member_list = list(members)
        for member in member_list:
            if role not in member.roles:
                await member.add_roles(role, reason=reason)
            tracked.add(member.id)
        self.state["btgo_role_member_ids"] = list(tracked)
        save_state(self.state)
        logger.info(
            "Applied BTGO role to %s members for reason '%s': %s",
            len(member_list),
            reason,
            ", ".join(member.display_name for member in member_list),
        )

    def prune_inspect_history(self) -> None:
        today = self.current_date_key()
        current = self.state.get("inspect_usage_by_user_date", {})
        self.state["inspect_usage_by_user_date"] = {
            user_id: used_date
            for user_id, used_date in current.items()
            if used_date == today
        }
        save_state(self.state)

    async def run_daily_shuffle(
        self,
        trigger: str,
        source_channel: Optional[discord.abc.Messageable] = None,
        guild: Optional[discord.Guild] = None,
    ) -> list[discord.Member]:
        logger.info("Running BTGO shuffle. trigger=%s source_channel=%s", trigger, bool(source_channel))
        target_guild = guild or await self.fetch_target_guild()
        role = self.resolve_btgo_role(target_guild)
        ibtc_role = self.resolve_ibtc_role(target_guild)

        await self.clear_btgo_roles(target_guild, role)
        await self.clear_ibtc_roles(ibtc_role)

        online_members = await self.get_online_humans(target_guild)
        if not online_members:
            self.state["last_daily_shuffle_date"] = self.current_date_key()
            save_state(self.state)
            logger.warning("No online members were eligible for BTGO shuffle.")

            if source_channel is not None:
                await self.send_character_message(
                    source_channel,
                    "no_online_users",
                    self.config.responses.no_online_users,
                )
            return []

        winners = self.choose_daily_winners(online_members)
        if not winners:
            self.state["last_daily_shuffle_date"] = self.current_date_key()
            save_state(self.state)
            logger.warning("No eligible members were available after always/never pass filters.")
            if source_channel is not None:
                await self.send_character_message(
                    source_channel,
                    "no_online_users",
                    self.config.responses.no_online_users,
                )
            return []

        await self.apply_btgo_to_members(role, winners, f"BTGO shuffle ({trigger})")

        self.state["last_daily_shuffle_date"] = self.current_date_key()
        save_state(self.state)

        values = {"winners": ", ".join(member.mention for member in winners)}
        logger.info(
            "Shuffle complete. Winners: %s",
            ", ".join(member.display_name for member in winners),
        )
        if source_channel is not None:
            await self.send_character_message(
                source_channel,
                "reshuffle_done",
                self.config.responses.reshuffle_done,
                values,
            )
        return winners

    def user_can_reshuffle(self, member: discord.Member) -> bool:
        if member.id in self.config.reshuffle_allowed_user_ids:
            logger.info("User %s allowed to reshuffle via explicit allowlist.", member.id)
            return True
        role = discord.utils.get(member.roles, name=self.config.btgo_role_identifier)
        if role is not None:
            logger.info("User %s allowed to reshuffle via BTGO role name match.", member.id)
            return True
        if self.config.btgo_role_identifier.isdigit():
            allowed = any(role.id == int(self.config.btgo_role_identifier) for role in member.roles)
            if allowed:
                logger.info("User %s allowed to reshuffle via BTGO role ID match.", member.id)
            return allowed
        logger.info("User %s denied reshuffle access.", member.id)
        return False

    def user_has_btgo_role(self, member: discord.Member) -> bool:
        """Check if a user has the BTGO role."""
        role = discord.utils.get(member.roles, name=self.config.btgo_role_identifier)
        if role is not None:
            return True
        if self.config.btgo_role_identifier.isdigit():
            return any(role.id == int(self.config.btgo_role_identifier) for role in member.roles)
        return False

    async def daily_shuffle_loop(self) -> None:
        await self.wait_until_ready()

        today = self.current_date_key()
        if self.state.get("last_daily_shuffle_date") != today:
            try:
                await self.run_daily_shuffle("startup")
                self.prune_inspect_history()
            except Exception:
                logger.exception("Startup shuffle failed.")

        while not self.is_closed():
            next_run = self.next_midnight()
            sleep_seconds = max(1, (next_run - datetime.now(self.timezone)).total_seconds())
            logger.info("Next scheduled shuffle in %.0f seconds.", sleep_seconds)
            await asyncio.sleep(sleep_seconds)
            try:
                await self.run_daily_shuffle("scheduled")
                self.prune_inspect_history()
            except Exception:
                logger.exception("Scheduled shuffle failed.")

    async def generate_mention_reply(self, message: discord.Message, has_btgo_role: bool) -> str:
        start_time = asyncio.get_running_loop().time()
        if not self.openai_client:
            response_pool = self.config.responses.mention_uwu if has_btgo_role else self.config.responses.mention_mean
            return await self.build_character_response("mention", response_pool)

        tone = "favorable and playful" if has_btgo_role else "dismissive and disdainful"
        user_content = message.content.strip() or "(no text, mention only)"

        try:
            logger.info(
                "Mention AI request user_id=%s btgo=%s model=%s",
                message.author.id,
                has_btgo_role,
                self.openai_model,
            )
            completion = await self.create_ai_response(
                "mention",
                [
                    {"role": "system", "content": self.config.ai_system_prompt},
                    {
                        "role": "user",
                        "content": (
                            "Reply as the bot to a Discord mention in one short message. "
                            f"Tone must be {tone}. User message: {user_content}. "
                            "No markdown. Keep it Discord-safe."
                        ),
                    },
                ],
            )
            output = (completion.output_text or "").strip()
            if output:
                elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
                logger.info(
                    "Mention AI response success user_id=%s elapsed_ms=%.0f chars=%s",
                    message.author.id,
                    elapsed_ms,
                    len(output),
                )
                return output
            elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            logger.warning(
                "Mention AI response empty user_id=%s elapsed_ms=%.0f; falling back.",
                message.author.id,
                elapsed_ms,
            )
        except Exception:
            elapsed_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            logger.exception(
                "AI mention reply failed user_id=%s elapsed_ms=%.0f; falling back.",
                message.author.id,
                elapsed_ms,
            )

        fallback_pool = self.config.responses.mention_uwu if has_btgo_role else self.config.responses.mention_mean
        return await self.build_character_response("mention", fallback_pool)

    async def get_ibtc_taunt_channel(self, guild: discord.Guild) -> Optional[discord.abc.Messageable]:
        if self.config.ibtc_taunt_channel_id:
            configured_channel = guild.get_channel(self.config.ibtc_taunt_channel_id)
            if configured_channel is not None:
                return configured_channel

        if guild.system_channel is not None:
            return guild.system_channel

        for channel in guild.text_channels:
            if channel.permissions_for(guild.me).send_messages:
                return channel
        return None

    async def ibtc_taunt_loop(self) -> None:
        await self.wait_until_ready()
        while not self.is_closed():
            base_seconds = self.config.ibtc_taunt_interval_minutes * 60
            sleep_seconds = random.uniform(base_seconds * 0.5, base_seconds * 1.5)
            await asyncio.sleep(max(10, sleep_seconds))

            try:
                guild = await self.fetch_target_guild()
                ibtc_role = self.resolve_ibtc_role(guild)
                if not ibtc_role.members:
                    continue

                eligible_members = [member for member in ibtc_role.members if not member.bot]
                if not eligible_members:
                    continue
                target_member = random.choice(eligible_members)

                channel = await self.get_ibtc_taunt_channel(guild)
                if channel is None:
                    logger.warning("Could not find an IBTC taunt channel in guild %s.", guild.id)
                    continue

                await self.send_character_message(
                    channel,
                    "ibtc_taunt",
                    self.config.responses.ibtc_taunt,
                    {"role": ibtc_role.mention, "target": target_member.mention},
                )
            except Exception:
                logger.exception("IBTC taunt loop iteration failed.")


config = load_config()
bot = BtgoBot(config)


@bot.event
async def on_ready() -> None:
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="staring down your shirt",
        )
    )
    logger.info("Logged in as %s", bot.user)
    logger.info(
        "AI config enabled=%s api_key_present=%s model=%s timeout_seconds=%.1f ai_percent=%s",
        bot.config.enable_ai_responses,
        bool(bot.config.openai_api_key),
        bot.openai_model,
        bot.config.openai_timeout_seconds,
        bot.config.ai_response_percent,
    )


@bot.event
async def on_message(message: discord.Message) -> None:
    """Handle direct messages and mentions."""
    message_start = asyncio.get_running_loop().time()

    # Ignore messages from bots
    if message.author.bot:
        return

    # Check if bot is mentioned in the message
    if bot.user and bot.user.mentioned_in(message):
        # Determine if author has BTGO role
        has_btgo_role = False
        if isinstance(message.author, discord.Member):
            has_btgo_role = bot.user_has_btgo_role(message.author)

        logger.info(
            "Mention received from %s (BTGO: %s) in %s",
            message.author.id,
            has_btgo_role,
            "DM" if isinstance(message.channel, discord.DMChannel) else "guild",
        )
        async with maybe_typing(message.channel):
            mention_reply = await bot.generate_mention_reply(message, has_btgo_role)
            await message.channel.send(mention_reply)

    # Check if this is a DM (direct message)
    elif isinstance(message.channel, discord.DMChannel):
        # Determine if author has BTGO role (requires member object, DMs don't have it)
        has_btgo_role = False
        if isinstance(message.author, discord.Member):
            has_btgo_role = bot.user_has_btgo_role(message.author)

        # Select response pool based on role
        if has_btgo_role:
            response_pool = bot.config.responses.dm_uwu
        else:
            response_pool = bot.config.responses.dm_mean

        logger.info("DM received from %s (BTGO: %s)", message.author.id, has_btgo_role)
        await bot.send_character_message(message.channel, "dm", response_pool)

    # Process commands normally
    await bot.process_commands(message)
    elapsed_ms = (asyncio.get_running_loop().time() - message_start) * 1000
    logger.info(
        "Message handling complete message_id=%s author_id=%s elapsed_ms=%.0f",
        message.id,
        message.author.id,
        elapsed_ms,
    )


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member) -> None:
    before_role_ids = {role.id for role in before.roles}
    after_role_ids = {role.id for role in after.roles}
    if before_role_ids == after_role_ids:
        return

    try:
        await bot.enforce_ibtc_precedence(
            after.guild,
            after,
            reason="IBTC precedence role sync",
        )
    except Exception:
        logger.exception("Failed to enforce IBTC precedence for member_id=%s", after.id)


@bot.command(name="help")
async def help_command(ctx: commands.Context[Any]) -> None:
    intro = await bot.build_character_response("help_intro", bot.config.responses.help_intro)
    prefix = bot.config.command_prefix
    lines = [
        intro,
        "",
        f"{prefix}help - Show commands.",
        f"{prefix}inspect [@user] - Willing to inspect tittes once per day.",
        f"{prefix}time - Show next daily role shuffle time.",
        f"{prefix}reshuffle - Force reshuffle if you are approved or currently BTGO.",
    ]
    await ctx.send("\n".join(lines))


@bot.command(name="time")
async def time_command(ctx: commands.Context[Any]) -> None:
    timestamp = int(bot.next_midnight().timestamp())
    await bot.send_character_message(
        ctx.channel,
        "time",
        bot.config.responses.time,
        {"nextTime": f"<t:{timestamp}:F>", "relativeTime": f"<t:{timestamp}:R>"},
    )


@bot.command(name="inspect")
async def inspect_command(ctx: commands.Context[Any], target: Optional[discord.Member] = None) -> None:
    logger.info("Inspect command invoked by %s targeting %s", ctx.author.id, getattr(target, "id", ctx.author.id))
    today = bot.current_date_key()
    user_id = str(ctx.author.id)
    used = bot.state.setdefault("inspect_usage_by_user_date", {})

    if used.get(user_id) == today:
        await bot.send_character_message(
            ctx.channel,
            "inspect_cooldown",
            bot.config.responses.inspect_cooldown,
        )
        return

    target_member = target or ctx.author
    used[user_id] = today
    save_state(bot.state)

    if bot.is_never_pass_user(target_member.id):
        if ctx.guild is not None and isinstance(ctx.author, discord.Member):
            await bot.assign_ibtc_role_to_member(ctx.guild, ctx.author, "Requester failed inspect (configured never-pass target)")
        await bot.send_character_message(
            ctx.channel,
            "inspect_fail",
            bot.config.responses.inspect_lose,
            {"target": target_member.mention},
        )
        return

    if bot.is_always_pass_user(target_member.id):
        guild = ctx.guild
        if guild is None:
            return
        role = bot.resolve_btgo_role(guild)
        member = target_member if isinstance(target_member, discord.Member) else ctx.author
        await bot.apply_btgo_to_members(role, [member], "Configured always-pass user")
        await bot.send_character_message(
            ctx.channel,
            "inspect_success",
            bot.config.responses.inspect_win,
            {"target": member.mention},
        )
        return

    if isinstance(target_member, discord.Member) and bot.user_has_btgo_role(target_member):
        await bot.send_character_message(
            ctx.channel,
            "inspect_already_btgo",
            bot.config.responses.inspect_already_btgo,
            {"target": target_member.mention},
        )
        return

    if random.uniform(0, 100) >= bot.config.inspect_success_percent:
        if ctx.guild is not None and isinstance(ctx.author, discord.Member):
            await bot.assign_ibtc_role_to_member(ctx.guild, ctx.author, "Requester failed inspect")
        await bot.send_character_message(
            ctx.channel,
            "inspect_fail",
            bot.config.responses.inspect_lose,
            {"target": target_member.mention},
        )
        return

    guild = ctx.guild
    if guild is None:
        return
    role = bot.resolve_btgo_role(guild)
    member = target_member if isinstance(target_member, discord.Member) else ctx.author
    await bot.apply_btgo_to_members(role, [member], "Manual inspect success")
    await bot.send_character_message(
        ctx.channel,
        "inspect_success",
        bot.config.responses.inspect_win,
        {"target": member.mention},
    )


@bot.command(name="reshuffle")
async def reshuffle_command(ctx: commands.Context[Any]) -> None:
    if ctx.guild is None or not isinstance(ctx.author, discord.Member):
        logger.warning("Reshuffle command ignored because context was not a guild member context.")
        return

    logger.info("Reshuffle command invoked by %s in guild %s", ctx.author.id, ctx.guild.id)
    if not bot.user_can_reshuffle(ctx.author):
        await bot.send_character_message(
            ctx.channel,
            "reshuffle_denied",
            bot.config.responses.reshuffle_denied,
        )
        return

    await bot.run_daily_shuffle("manual", ctx.channel, ctx.guild)


@bot.command(name="clear", hidden=True)
async def clear_command(ctx: commands.Context[Any]) -> None:
    if ctx.guild is None or not isinstance(ctx.author, discord.Member):
        logger.warning("Clear command ignored because context was not a guild member context.")
        return

    if not ctx.author.guild_permissions.administrator:
        logger.warning("Clear command denied for non-admin user %s", ctx.author.id)
        await ctx.send("Only server admins can use this command.")
        return

    ibtc_role = bot.resolve_ibtc_role(ctx.guild)
    cleared_ibtc_count = await bot.clear_ibtc_roles(ibtc_role, reason=f"Manual clear command by {ctx.author.id}")

    bot.state["inspect_usage_by_user_date"] = {}
    save_state(bot.state)
    logger.info(
        "Clear command complete by admin %s; inspect cooldown reset and IBTC cleared_count=%s",
        ctx.author.id,
        cleared_ibtc_count,
    )
    await ctx.send(
        f"Cleared IBTC role from {cleared_ibtc_count} member(s). Inspect cooldown usage has also been reset."
    )


@bot.event
async def on_command_error(ctx: commands.Context[Any], error: commands.CommandError) -> None:
    if isinstance(error, commands.CommandNotFound):
        return
    logger.exception("Command error while handling message '%s'", getattr(ctx.message, "content", ""), exc_info=error)
    await bot.send_character_message(
        ctx.channel,
        "generic_error",
        bot.config.responses.generic_error,
    )


async def main() -> None:
    async with bot:
        await bot.start(config.token)


if __name__ == "__main__":
    asyncio.run(main())
