from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

import discord
from discord.ext import commands
from openai import AsyncOpenAI

from config_parse import Config, load_config

DATA_DIR = Path("data")
STATE_PATH = DATA_DIR / "state.json"
BOT_LOG_PATH = DATA_DIR / "bot.log"

DATA_DIR.mkdir(parents=True, exist_ok=True)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BOT_LOG_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("btgo")


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
        self.openai_client = (
            AsyncOpenAI(api_key=config.openai_api_key)
            if config.enable_ai_responses and config.openai_api_key
            else None
        )
        self.daily_task: Optional[asyncio.Task[None]] = None

    async def setup_hook(self) -> None:
        logger.info("Starting daily shuffle background task.")
        self.daily_task = asyncio.create_task(self.daily_shuffle_loop())

    async def close(self) -> None:
        if self.daily_task:
            self.daily_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.daily_task
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
        fallback = format_with_vars(self.pick_response(response_pool), values)

        if not self.should_use_ai():
            return fallback

        try:
            openai_client = self.openai_client
            if openai_client is None:
                return fallback

            variable_lines = "\n".join(f"{key}: {value}" for key, value in values.items())
            prompt = [
                f"Write one short Discord message for context: {context_name}.",
                "Stay in persona and keep it concise.",
                "Do not include markdown.",
            ]
            if variable_lines:
                prompt.append(f"Variables:\n{variable_lines}")

            completion = await openai_client.responses.create(
                model=self.config.openai_model,
                input=[
                    {"role": "system", "content": self.config.ai_system_prompt},
                    {"role": "user", "content": "\n".join(prompt)},
                ],
            )
            output = (completion.output_text or "").strip()
            return output or fallback
        except Exception:
            return fallback

    async def send_character_message(
        self,
        destination: discord.abc.Messageable,
        context_name: str,
        response_pool: list[str],
        values: Optional[dict[str, Any]] = None,
    ) -> discord.Message:
        content = await self.build_character_response(context_name, response_pool, values)
        return await destination.send(content)

    async def fetch_target_guild(self) -> discord.Guild:
        guild = self.get_guild(self.config.guild_id)
        if guild is None:
            logger.info("Guild %s was not cached; fetching from API.", self.config.guild_id)
            guild = await self.fetch_guild(self.config.guild_id)
        if not isinstance(guild, discord.Guild):
            raise RuntimeError("Configured guild could not be loaded.")
        await guild.chunk(cache=True)
        return guild

    def resolve_role(self, guild: discord.Guild) -> discord.Role:
        identifier = self.config.btgo_role_identifier
        role = None
        if identifier.isdigit():
            role = guild.get_role(int(identifier))
        if role is None:
            role = discord.utils.get(guild.roles, name=identifier)
        if role is None:
            raise RuntimeError("Configured BTGO role was not found.")
        return role

    async def clear_btgo_roles(self, guild: discord.Guild, role: discord.Role) -> None:
        logger.info("Clearing BTGO role from %s current holders.", len(role.members))
        for member in list(role.members):
            await member.remove_roles(role, reason="Daily BTGO reset")
        self.state["btgo_role_member_ids"] = []
        save_state(self.state)

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
        role = self.resolve_role(target_guild)

        await self.clear_btgo_roles(target_guild, role)

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

        count = self.get_daily_winner_count(len(online_members))
        winners = random.sample(online_members, count)
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


@bot.event
async def on_message(message: discord.Message) -> None:
    """Handle direct messages and mentions."""
    # Ignore messages from bots
    if message.author.bot:
        return

    # Check if bot is mentioned in the message
    if bot.user and bot.user.mentioned_in(message):
        # Determine if author has BTGO role
        has_btgo_role = False
        if isinstance(message.author, discord.Member):
            has_btgo_role = bot.user_has_btgo_role(message.author)

        # Select response pool based on role and context
        if has_btgo_role:
            response_pool = bot.config.responses.mention_uwu
        else:
            response_pool = bot.config.responses.mention_mean

        logger.info(
            "Mention received from %s (BTGO: %s) in %s",
            message.author.id,
            has_btgo_role,
            "DM" if isinstance(message.channel, discord.DMChannel) else "guild",
        )
        await bot.send_character_message(message.channel, "mention", response_pool)

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

    if isinstance(target_member, discord.Member) and bot.user_has_btgo_role(target_member):
        await bot.send_character_message(
            ctx.channel,
            "inspect_already_btgo",
            bot.config.responses.inspect_already_btgo,
            {"target": target_member.mention},
        )
        return

    if random.uniform(0, 100) >= bot.config.inspect_success_percent:
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
    role = bot.resolve_role(guild)
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

    bot.state["inspect_usage_by_user_date"] = {}
    save_state(bot.state)
    logger.info("Inspect usage cooldown state cleared by admin %s", ctx.author.id)
    await ctx.send("Inspect cooldown usage has been cleared. Everyone can try !inspect again.")


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
