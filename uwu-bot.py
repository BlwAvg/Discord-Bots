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
from discord.ext import commands, tasks
import discord

# setup notes
#sudo apt install libffi-dev libnacl-dev python3-dev pip python3-venv ffmpeg
#python3 -m venv .venv
#source .venv/bin/activate
# python3 -m pip install -U discord.py[voice] --- A bug for voice in v2.5.2 use repo below
#pip install --upgrade git+https://github.com/Rapptz/discord.py.git@master
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

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="UwU"))
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print('------')
    if not join_and_uwu.is_running():
        join_and_uwu.start()

@tasks.loop(minutes=30)
async def join_and_uwu():
    """
    Every 30 minutes, picks a random voice channel with active users,
    joins it, plays a random MP3 from your designated folder, then disconnects.
    """
    # Collect voice channels that have at least one member besides the bot
    voice_channels = []
    for guild in bot.guilds:
        for channel in guild.voice_channels:
            perms = channel.permissions_for(guild.me)
            if perms.connect and perms.speak and len(channel.members) > 0:
                voice_channels.append(channel)

    if not voice_channels:
        return  # no active channels available

    channel = random.choice(voice_channels) # Choose random voice channel
    try:
        vc = await channel.connect()
    except discord.ClientException:
        vc = discord.utils.get(bot.voice_clients, guild=channel.guild)
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    # Choose a random MP3 file from the folder
    if not os.path.isdir(uwu_folder):
        print(f"UwU folder not found at '{uwu_folder}'")
    else:
        files = [f for f in os.listdir(uwu_folder) if f.lower().endswith('.mp3')]
        if not files:
            print(f"No MP3 files in folder '{uwu_folder}'")
        else:
            selected = random.choice(files)
            filepath = os.path.join(uwu_folder, selected)
            audio = discord.FFmpegPCMAudio(filepath)
            vc.play(audio)
            while vc.is_playing():
                await asyncio.sleep(1)

    await vc.disconnect()

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
