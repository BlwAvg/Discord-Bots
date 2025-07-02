# Discord Nmap Scanner Bot
# Send nmap scans to the bot and it will do a scan for you.
# - Listens for !scan commands in Discord and runs Nmap with various options
# - Supports TCP top-ports, version detection, OS detection, UDP scan, and ping-only
# - Resolves hostnames, blocks RFC1918 private and loopback ranges
# - Prevents concurrent scans per user and returns formatted results in-channel
# - Logs every command invocation to a rotating file (commands.log)
# - Custom !help command lists available scans and detailed usage
# - Uses asyncio to run scans off the main thread for non-blocking operation


import discord
import socket
import ipaddress
import asyncio
import time
import nmap
import logging
from logging.handlers import RotatingFileHandler
from discord.ext import commands

# *********setup stuff************
#python3 -m venv .venv
#source .venv/bin/activate
#python3 -m pip install -U discord.py
#python3 pip install python-nmap
#deactivate
#https://discord.com/oauth2/authorize?client_id=YOUR_APPID_HERE_I_THINK&permissions=395137068032&integration_type=0&scope=bot+applications.commands

# - Neet to allow permissions for OS scanning.
# - Need to allow for raw output via code box.
# *********************************

# ----------------------------------------
# Configuration
# ----------------------------------------
# Hardcoded Discord bot token (replace with your actual token)
TOKEN = 'YOUR MOMS TOKEN HERE'

# Block RFC1918 private networks to prevent internal scanning
PRIVATE_NETWORKS = [
    ipaddress.IPv4Network('10.0.0.0/8'),        # 10.0.0.0 – 10.255.255.255
    ipaddress.IPv4Network('172.16.0.0/12'),     # 172.16.0.0 – 172.31.255.255
    ipaddress.IPv4Network('192.168.0.0/16')     # 192.168.0.0 – 192.168.255.255
]
# Block loopback addresses as well
LOOPBACK_NETWORK = ipaddress.IPv4Network('127.0.0.0/8')  # 127.0.0.0 – 127.255.255.255

# ----------------------------------------
# Bot Initialization
# ----------------------------------------
# Configure intents to access message content and guild data
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

# Create bot with intents and disable default help
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Dictionary to track active scans by user ID
active_scans = {}  # { user_id: { 'task': asyncio.Task, 'target': str, 'start_time': float, 'name': str } }


# ----------------------------------------
# Command Logging Setup
# ----------------------------------------
# Create a dedicated logger for command usage
cmd_logger = logging.getLogger('command_logger')
cmd_logger.setLevel(logging.INFO)

# Rotate log at 5 MB, keep last 3 files
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
    """
    Called when the bot successfully connects to Discord.
    Prints the bot's username and ID to the console.
    """
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')

@bot.event
async def on_command(ctx):
    """
    Called whenever a valid command is invoked.
    Logs user, guild, channel, command, and full message.
    """
    user = f"{ctx.author} ({ctx.author.id})"
    guild = f"{ctx.guild.name} ({ctx.guild.id})" if ctx.guild else "DM"

    # Safely get channel name, default to "DM" if attribute missing
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
    """
    Check if an IP address string falls within a forbidden network.
    Returns the network if forbidden, otherwise None.
    """
    ip_obj = ipaddress.ip_address(ip_str)
    for net in PRIVATE_NETWORKS + [LOOPBACK_NETWORK]:
        if ip_obj in net:
            return net
    return None

def resolve_and_validate(target):
    """
    Resolve a hostname to an IP address and validate it's not forbidden.
    Raises ValueError on resolution failure or forbidden address.
    Returns the resolved IP string.
    """
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
    Execute an Nmap scan with the provided arguments in a separate thread.
    Sends formatted scan results back to the Discord channel.
    """
    nm = nmap.PortScanner()
    try:
        await asyncio.to_thread(nm.scan, hosts=target, arguments=nmap_args)
    except Exception as e:
        await ctx.send(f"⚠️ Scan error: {e}")
        return

    hosts = nm.all_hosts()
    if not hosts:
        # DM the user if you prefer private notifications:
        # await ctx.author.send(f"❌ Host {target} appears down or unresponsive.")
        await ctx.send(f"{ctx.author.mention} ❌ Host {target} appears down or unresponsive.")
        return

    host = hosts[0]
    lines = [f"**Scan results for {target} ({host}):**"]
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            state = nm[host][proto][port]['state']
            service = nm[host][proto][port].get('name', '')
            lines.append(f"- {proto.upper()}/{port}: {state} ({service})")

    max_lines = 50
    output = "\n".join(lines[:max_lines])
    if len(lines) > max_lines:
        output += "\n… and more."

    # Ping them in-channel:
    await ctx.send(f"{ctx.author.mention} ✅ Your `{ctx.command.name}` scan on `{target}` is complete:\n{output}")

    # — Or, if you'd rather DM them—
    # await ctx.author.send(f"✅ Your `{ctx.command.name}` scan on `{target}` is complete:\n{output}")

# ----------------------------------------
# Command Factory (with proper help strings)
# ----------------------------------------
def make_scan_command(name, description, nmap_args):
    """
    Dynamically creates a scan command.

    name        – the literal text after '!' (e.g. 'scan_v')
    description – shown in help listings
    nmap_args   – args to pass to nmap
    """
    @bot.command(
        name=name,
        help=description                # embed description in the Command object
    )
    async def _cmd(ctx, target: str):
        """
        Actual command callback: resolves/validates target, starts scan.
        """
        user_id = ctx.author.id

        # Prevent concurrent scans per-user
        if user_id in active_scans and not active_scans[user_id]['task'].done():
            entry = active_scans[user_id]
            elapsed = int(time.time() - entry['start_time'])
            await ctx.send(
                f"⚠️ A scan (`{entry['name']}` on {entry['target']}) "
                f"is still running (elapsed {elapsed}s). Please wait."
            )
            return

        # Hostname → IP, block private/loopback networks
        try:
            resolve_and_validate(target)
        except ValueError as e:
            await ctx.send(f"❌ {e}")
            return

        # Launch the scan in background
        task = asyncio.create_task(run_nmap(ctx, target, nmap_args))
        active_scans[user_id] = {
            'task': task,
            'target': target,
            'start_time': time.time(),
            'name': name
        }
        await ctx.send(f"🔍 Started `{name}` on {target}. I’ll let you know when it’s done.")

    # Also set the docstring for introspection (optional)
    _cmd.__doc__ = description
    return _cmd

# ----------------------------------------
# Register Scan Commands
# ----------------------------------------
# command, description, nmap arguments
make_scan_command('scan',       'Top 1000 TCP ports',               '-Pn -T4 --top-ports 1000')
make_scan_command('scan_v',     'Version detection (-sV)',          '-Pn -sV -T4')
make_scan_command('scan_o',     'OS detection (-O)',                '-Pn -O -T4')
make_scan_command('scan_u',     'Top 100 UDP ports (-sU)',          '-Pn -sU --top-ports 100')
make_scan_command('scan_ping',  'Ping scan (host discovery only)',  '-sn')

# ----------------------------------------
# Help Command Registration
# ----------------------------------------
# Remove any existing help so ours takes over
bot.remove_command('help')

@bot.command(name='help', help="Show this menu or detailed help for a command.")
async def help_cmd(ctx, command_name: str = None):
    """
    Show this help menu, or detailed help for a single command.

    If no command_name is provided, lists all available commands.
    If a command_name is provided, shows the description for that command.
    """
    # — If they want details for one command —
    if command_name:
        cmd = bot.get_command(command_name)
        if cmd and not cmd.hidden:
            await ctx.send(f"**`!{cmd.name}`** – {cmd.help}")
        else:
            await ctx.send(f"❌ No such command: `{command_name}`")
        return

    # — Otherwise, assemble a full list —
    lines = ["**Available commands:**"]
    for cmd in bot.commands:
        # Skip hidden and subcommands
        if cmd.hidden or cmd.parent:
            continue
        lines.append(f"- `!{cmd.name}`: {cmd.help or 'No description.'}")

    await ctx.send("\n".join(lines))

# ----------------------------------------
# Entry Point
# ----------------------------------------
if __name__ == '__main__':
    """
    Starts the Discord bot using the hardcoded TOKEN.
    """
    if not TOKEN:
        print('Error: Discord token is not set.')
    else:
        bot.run(TOKEN)
