# Discord “UwU” Voice Bot
# Joins a random, occupied voice chat. Picks a random mp3 from the sounds folder, plays the sound and then leave voice chat.
# - Automatically joins a random active voice channel every 30 minutes
# - Plays a random MP3 from a specified folder, then disconnects
# - Administrator command !setinterval to adjust the loop frequency
# - User !start or !stop command for starting or stopping the bot
# - Logs in with a hardcoded token and sets presence to “Watching UwU”
# - Requires FFmpeg and discord.py[voice] for audio playback

import os
import random
import asyncio
import logging
from discord.ext import commands, tasks
import discord

# setup notes
#sudo apt install libffi-dev libnacl-dev python3-dev pip python3-venv ffmpeg
#python3 -m venv .venv
#source .venv/bin/activate
# python3 -m pip install -U discord.py[voice] pynacl davey --- A bug for voice in v2.5.2 use repo below
# pip install --upgrade git+https://github.com/Rapptz/discord.py.git@master 
#deactivate

# Bot setup --- Hard-coded settings ---
token = "Your Mothers Token Goes Here"
uwu_folder = "/uwu/sounds/dir/here"   # full absolute path to your MP3 folder
prefix = '!'

intents = discord.Intents.default()
intents.message_content = True
intents.voice_states = True
intents.guilds = True

bot = commands.Bot(command_prefix=prefix, intents=intents)
logger = logging.getLogger("uwu_bot")

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def ensure_voice(channel: discord.VoiceChannel) -> discord.VoiceClient | None:
    """Return a connected voice client for channel.guild, reconnecting/moving if needed."""
    guild = channel.guild
    existing_vc = discord.utils.get(bot.voice_clients, guild=guild)
    vc = existing_vc if isinstance(existing_vc, discord.VoiceClient) else None

    try:
        if vc and vc.is_connected():
            if vc.channel and vc.channel.id != channel.id:
                logger.info(
                    "Moving in guild '%s' from '%s' to '%s'",
                    guild.name,
                    vc.channel.name,
                    channel.name,
                )
                await vc.move_to(channel)
            return vc

        if vc and not vc.is_connected():
            logger.warning(
                "Stale voice client detected in guild '%s'; reconnecting",
                guild.name,
            )
            try:
                await vc.disconnect(force=True)
            except Exception:
                logger.exception(
                    "Error while cleaning stale voice client in guild '%s'",
                    guild.name,
                )

        logger.info("Connecting to '%s' in guild '%s'", channel.name, guild.name)
        vc = await channel.connect(reconnect=True, self_deaf=True)

        if not vc or not vc.is_connected():
            logger.error(
                "Voice connect returned disconnected client for guild '%s'",
                guild.name,
            )
            return None

        return vc
    except Exception:
        logger.exception(
            "Failed to establish voice connection for guild '%s' channel '%s'",
            guild.name,
            channel.name,
        )
        return None

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="UwU"))
    if bot.user is not None:
        print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    else:
        print('Logged in, but bot user is unexpectedly None')
    print('------')
    if not join_and_uwu.is_running():
        join_and_uwu.start()

@tasks.loop(minutes=30)
async def join_and_uwu():
    """
    Every 30 minutes, picks a random voice channel with active users,
    joins it, plays a random MP3 from your designated folder, then disconnects.
    """
    vc: discord.VoiceClient | None = None
    try:
        # Collect channels with at least one non-bot member.
        voice_channels = []
        for guild in bot.guilds:
            me = guild.me
            if me is None:
                continue
            for channel in guild.voice_channels:
                perms = channel.permissions_for(me)
                has_human = any(not member.bot for member in channel.members)
                if perms.connect and perms.speak and has_human:
                    voice_channels.append(channel)

        if not voice_channels:
            logger.info("No eligible voice channels with non-bot users found")
            return

        channel = random.choice(voice_channels)
        guild = channel.guild
        logger.info("Selected channel '%s' in guild '%s'", channel.name, guild.name)

        vc = await ensure_voice(channel)
        if vc is None or not vc.is_connected():
            logger.error(
                "Skipping playback because voice is unavailable in guild '%s'",
                guild.name,
            )
            return

        if not os.path.isdir(uwu_folder):
            logger.error("UwU folder not found at '%s'", uwu_folder)
            return

        files = [f for f in os.listdir(uwu_folder) if f.lower().endswith('.mp3')]
        if not files:
            logger.warning("No MP3 files in folder '%s'", uwu_folder)
            return

        selected = random.choice(files)
        filepath = os.path.join(uwu_folder, selected)
        audio = discord.FFmpegPCMAudio(filepath)

        if not vc.is_connected():
            logger.error(
                "Voice client disconnected before playback in guild '%s'",
                guild.name,
            )
            return

        if vc.is_playing():
            vc.stop()

        try:
            vc.play(audio)
            logger.info(
                "Playback started in guild '%s' channel '%s': %s",
                guild.name,
                channel.name,
                selected,
            )
        except Exception:
            logger.exception(
                "Playback error in guild '%s' channel '%s'",
                guild.name,
                channel.name,
            )
            return

        while vc.is_connected() and vc.is_playing():
            await asyncio.sleep(1)

    except Exception:
        # Keep loop alive if one run fails unexpectedly.
        logger.exception("Unexpected error in join_and_uwu loop run")
    finally:
        if vc and vc.is_connected():
            try:
                await vc.disconnect()
                logger.info("Disconnected from guild '%s'", vc.guild.name)
            except Exception:
                logger.exception("Failed to disconnect cleanly")


@join_and_uwu.error
async def join_and_uwu_error(*args):
    # Final safety net for exceptions escaping the loop body.
    error = args[-1] if args else Exception("Unknown join_and_uwu task error")
    logger.exception("join_and_uwu task error: %s", error)

# Manual trigger:
@bot.command(name='run')
async def run_uwu(ctx):
    """Manually trigger one UwU playthrough."""
    await ctx.send("🎶 Running UwU now!")
    await join_and_uwu()

# Command to change interval (optional)
@bot.command(name='setinterval')
@commands.has_permissions(administrator=True)
async def set_interval(ctx, minutes: int):
    """Allows server admins to change the loop interval."""
    join_and_uwu.change_interval(minutes=minutes)
    await ctx.send(f"Loop interval set to {minutes} minutes.")

# Start the auto-join loop
@bot.command(name='start')
@commands.is_owner()
async def start_uwu(ctx):
    if not join_and_uwu.is_running():
        join_and_uwu.start()
        await ctx.send("✅ UwU loop started.")
    else:
        await ctx.send("⚠️ UwU loop is already running.")

# Stop the auto-join loop
@bot.command(name='stop')
@commands.is_owner()
async def stop_uwu(ctx):
    if join_and_uwu.is_running():
        join_and_uwu.cancel()
        await ctx.send("⏸️ UwU loop stopped.")
    else:
        await ctx.send("⚠️ UwU loop is not running.")

if __name__ == '__main__':
    if not token:
        print("Error: BOT_TOKEN environment variable not set.")
        exit(1)
    print(f"Using UwU folder: {uwu_folder}")
    bot.run(token)
