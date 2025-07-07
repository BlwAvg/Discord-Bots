# Discord Nmap Scanner Bot
# A Discord bot that runs Nmap scans on demand and returns both a concise summary
# and the full raw output in a code block.
# - Listens for !scan, !scan_v, !scan_o, !scan_u, !scan_ping, and !scan_custom
# - Supports custom nmap arguments via !scan_custom
# - Blocks RFC1918 private and loopback ranges; rejects whole‐subnet targets
# - Warns on RFC5735 special‐use addresses but still proceeds
# - Enforces single‐IP targets, disallowing CIDR scans
# - Parses and formats port/service results, then appends raw Nmap stdout
# - Prevents concurrent scans per user
# - Logs every invocation to a rotating commands.log file
# - Uses asyncio + subprocess for non‐blocking scan execution
# - Token can be loaded from an environment variable for security

import discord
import socket
import ipaddress
import asyncio
import time
import subprocess
import shlex
import logging
from logging.handlers import RotatingFileHandler
from discord.ext import commands

# *********setup stuff************
# python3 -m venv .venv
# source .venv/bin/activate
# python3 -m pip install -U discord.py
# python3 -m pip install -U python-nmap
# deactivate
# https://discord.com/oauth2/authorize?client_id=YOUR_APPID_HERE&permissions=395137068032&scope=bot+applications.commands
# - Need to allow permissions for OS scanning.
# - Responses now include raw Nmap output in a code block.
# *********************************

# ----------------------------------------
# Configuration
# ----------------------------------------

TOKEN = 'Your_mothers_discord_token_here'
# You can also use an env variable if you want. This is sometimes flaky, no idea why.
# os.environ['DISCORD_TOKEN']


# Deny scanning of RFC 1918
PRIVATE_NETWORKS = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16')
]

# Deny loopback scanning
LOOPBACK_NETWORK = ipaddress.IPv4Network('127.0.0.0/8')

# RFC 5735 special‐use networks (warn but allow)
RFC5735_NETWORKS = [
    ipaddress.IPv4Network('0.0.0.0/8'),   # “This” network
    ipaddress.IPv4Network('224.0.0.0/4'), # Multicast
    ipaddress.IPv4Network('240.0.0.0/4'), # Reserved
    ]

# ----------------------------------------
# Bot Initialization
# ----------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
active_scans = {}  # { user_id: { 'task': asyncio.Task, 'target': str, 'start_time': float, 'name': str } }

# ----------------------------------------
# Command Logging Setup
# ----------------------------------------
cmd_logger = logging.getLogger('command_logger')
cmd_logger.setLevel(logging.INFO)
handler = RotatingFileHandler(
    filename='commands.log',
    mode='a',
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding='utf-8',
)
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
cmd_logger.addHandler(handler)

# ----------------------------------------
# Event Handlers
# ----------------------------------------
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')

@bot.event
async def on_command(ctx):
    user = f"{ctx.author} ({ctx.author.id})"
    guild = f"{ctx.guild.name} ({ctx.guild.id})" if ctx.guild else "DM"
    channel_name = getattr(ctx.channel, 'name', 'DM')
    channel = f"{channel_name} ({ctx.channel.id})"
    cmd = ctx.command.qualified_name
    content = ctx.message.content
    cmd_logger.info(
        f"user={user} | guild={guild} | channel={channel} "
        f"| command={cmd} | message=\"{content}\""
    )

# ----------------------------------------
# Helper Functions
# ----------------------------------------
def is_forbidden(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    for net in PRIVATE_NETWORKS + [LOOPBACK_NETWORK]:
        if ip_obj in net:
            return net
    return None

def resolve_and_validate(target):
    #----------------------------------------
    # Disallow whole‐subnet scans 
    #----------------------------------------
    if '/' in target:
        try:
            # if this parses, it really is a network/subnet. If you want to allow subenets
            # change to this ipaddress.ip_network(target, strict=False)
            ipaddress.ip_network(target)
        except ValueError:
            # not a valid network spec (e.g. a hostname containing “/”), so keep going
            pass
        else:
            # a valid subnet: bail out with our custom message
            raise ValueError("You can only scan a single IP and not an entire subnet.")

    try:
        ip_str = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {target}")
    forbidden = is_forbidden(ip_str)
    if forbidden:
        raise ValueError(f"Scanning addresses in {forbidden} is not allowed.")
    return ip_str

async def run_nmap(ctx, target, nmap_args):
    """
    Execute an Nmap scan via subprocess, parse a brief summary,
    and always include the full raw output in a code block.
    """
    cmd = ['nmap'] + shlex.split(nmap_args) + [target]
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        raw = proc.stdout
    except Exception as e:
        await ctx.send(f"⚠️ Scan error: {e}")
        return

    # Parse a concise port/service summary
    summary = []
    lines = raw.splitlines()
    # find the "PORT" header
    header_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("PORT"):
            header_idx = i
            break
    if header_idx is not None:
        for line in lines[header_idx+1:]:
            if not line.strip():
                break
            parts = line.split()
            # only parse rows where the first column is port/proto
            if len(parts) >= 3 and '/' in parts[0]:
                port_proto = parts[0]
                state      = parts[1]
                service    = parts[2]
                # split only on the first slash to avoid surprises
                proto, port = port_proto.split('/', 1)
                summary.append(f"- {proto.upper()}/{port}: {state} ({service})")

    # Limit summary length
    max_lines = 50
    brief = "\n".join(summary[:max_lines])
    if len(summary) > max_lines:
        brief += "\n… and more."

    # Build and send the response
    header = f"{ctx.author.mention} ✅ Your `{ctx.command.name}` scan on `{target}` is complete:"
    raw_block = f"```{raw}```"
    if brief:
        message = f"{header}\n{brief}\n\n**Raw output:**\n{raw_block}"
    else:
        message = f"{header}\n(No open ports/services found in summary.)\n\n**Raw output:**\n{raw_block}"
    await ctx.send(message)

# ----------------------------------------
# Command Factory
# ----------------------------------------
def make_scan_command(name, description, nmap_args):
    @bot.command(name=name, help=description)
    async def _cmd(ctx, target: str):
        user_id = ctx.author.id
        if user_id in active_scans and not active_scans[user_id]['task'].done():
            entry = active_scans[user_id]
            elapsed = int(time.time() - entry['start_time'])
            await ctx.send(
                f"⚠️ A scan (`{entry['name']}` on {entry['target']}) "
                f"is still running (elapsed {elapsed}s). Please wait."
            )
            return
        try:
            ip_str = resolve_and_validate(target)
        except ValueError as e:
            await ctx.send(f"❌ {e}")
            return

        # warn on RFC 5735
        ip_obj = ipaddress.ip_address(ip_str)
        for net in RFC5735_NETWORKS:
            if ip_obj in net:
                await ctx.send("⚠️ I am RFC 5735 aware, but I’m still going to send it.")
                break

        task = asyncio.create_task(run_nmap(ctx, target, nmap_args))
        active_scans[user_id] = {
            'task': task,
            'target': target,
            'start_time': time.time(),
            'name': name
        }
        await ctx.send(f"🔍 Started `{name}` on {target}. I’ll let you know when it’s done.")
    _cmd.__doc__ = description
    return _cmd

# ----------------------------------------
# Register Scan Commands
# ----------------------------------------
make_scan_command('scan',       'Top 1000 TCP ports',               '-Pn -T4 --top-ports 1000')
make_scan_command('scan_v',     'Version detection (-sV)',          '-Pn -sV -T4')
make_scan_command('scan_o',     'OS detection (-O)',                '-Pn -O -T4')
make_scan_command('scan_u',     'Top 100 UDP ports (-sU)',          '-Pn -sU --top-ports 100')
make_scan_command('scan_ping',  'Ping scan (host discovery only)',  '-sn')

# ----------------------------------------
# Custom Scan Command
# ----------------------------------------
@bot.command(name='scan_custom', help='Custom nmap scan: specify any nmap arguments eg !scan_custom example.com -p 80,443 -sV')
async def scan_custom(ctx, target: str, *, nmap_args: str):
    """
    Custom scan: user-specified nmap arguments.
    Usage: !scan_custom <target> <nmap arguments>
    """
    user_id = ctx.author.id
    if user_id in active_scans and not active_scans[user_id]['task'].done():
        entry = active_scans[user_id]
        elapsed = int(time.time() - entry['start_time'])
        await ctx.send(
            f"⚠️ A scan (`{entry['name']}` on {entry['target']}) "
            f"is still running (elapsed {elapsed}s). Please wait."
        )
        return

    try:
        ip_str = resolve_and_validate(target)
    except ValueError as e:
        await ctx.send(f"❌ {e}")
        return

    # warn on RFC 5735
    ip_obj = ipaddress.ip_address(ip_str)
    for net in RFC5735_NETWORKS:
     if ip_obj in net:
         await ctx.send("⚠️ I am RFC 5735 aware, but I’m still going to send it.")
         break

    task = asyncio.create_task(run_nmap(ctx, target, nmap_args))
    active_scans[user_id] = {
        'task': task,
        'target': target,
        'start_time': time.time(),
        'name': 'scan_custom'
    }
    await ctx.send(f"🔍 Started `scan_custom` on {target} with args `{nmap_args}`. I’ll let you know when it’s done.")

# ----------------------------------------
# Help Command Registration
# ----------------------------------------
bot.remove_command('help')

@bot.command(name='help', help="Show this menu or detailed help for a command.")
async def help_cmd(ctx, command_name: str = None):
    if command_name:
        cmd = bot.get_command(command_name)
        if cmd and not cmd.hidden:
            await ctx.send(f"**`!{cmd.name}`** – {cmd.help}")
        else:
            await ctx.send(f"❌ No such command: `{command_name}`")
        return

    lines = ["**Available commands:**"]
    for cmd in bot.commands:
        if cmd.hidden or cmd.parent:
            continue
        lines.append(f"- `!{cmd.name}`: {cmd.help or 'No description.'}")
    await ctx.send("\n".join(lines))

# ----------------------------------------
# Entry Point
# ----------------------------------------
if __name__ == '__main__':
    if not TOKEN:
        print('Error: Discord token is not set.')
    else:
        bot.run(TOKEN)
