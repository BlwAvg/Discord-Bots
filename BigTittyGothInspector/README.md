# Big Titty Goth Inspector Bot

A Python Discord bot that runs a daily BTGO role shuffle and supports manual inspection commands.

## Features

- Daily at midnight (configured timezone), clears previous BTGO holders and picks random online users.
- Chooses a random winner count between configured minimum and maximum (default 2-5).
- `!inspect [@user]` gives a daily chance to assign BTGO role once per requester per day.
- `!inspect` failures now assign the configured IBTC role to the user who ran the command.
- Configurable `ALWAYS_PASS_USER_IDS` and `NEVER_PASS_USER_IDS` affect both `!inspect` and daily BTGO shuffle outcomes.
- IBTC role holders are also cleared during the daily reset alongside BTGO holders.
- `!time` shows when the next daily shuffle happens.
- `!reshuffle` can be used by allowed user IDs and current BTGO holders.
- `!help` command explains available commands.
- Response pools are configurable in `.env`.
- `!inspect` success chance is configurable via `INSPECT_SUCCESS_PERCENT`.
- Optional OpenAI response generation for in-character replies.
- Configurable AI response percentage when AI mode is enabled.
- Mentions use AI-generated role-aware tone when AI mode is enabled (favorable for BTGO holders, disdain for others).
- Periodic IBTC taunts select one random IBTC member to mention at configurable intervals.
- Runtime logs are written under `data/`.

## Setup

1. Create `.env` from the template and set at least:

```bash
cp .env.example .env
```

- `DISCORD_BOT_TOKEN`
- `GUILD_ID`
- `BTGO_ROLE_ID` (role ID or exact role name)
- `IBTC_ROLE_ID` (role ID or exact role name)

2. Install dependencies:

```bash
./install.sh
```

If you are on Windows, run the scripts from Git Bash or WSL.

3. In the Discord developer portal, enable:

- Server Members Intent
- Presence Intent
- Message Content Intent

4. Start the bot:

```bash
./start.sh
```

Manual entrypoint: `python -u bigtittygothinspector.py`

## Command Reference

- `!help`
- `!inspect [@user]`
- `!time`
- `!reshuffle`

## Notes

- Daily state is stored in `data/state.json`.
- Bot runtime logs are written to `data/bot.log`.
- Launcher logs are written to `data/start.log`.
- Installer logs are written to `data/install.log`.
- Scheduled daily shuffles do not post a separate announcement message.
- If AI responses are enabled but OpenAI fails, bot falls back to canned responses.
- `AI_RESPONSE_PERCENT` controls how often AI is attempted when AI is enabled.
- Mention replies try AI first and include the user's message content for context.
- `IBTC_TAUNT_INTERVAL_MINUTES` controls approximate taunt cadence with randomized spacing.
- `IBTC_TAUNT_CHANNEL_ID` is optional; if omitted, bot uses system channel or first writable text channel.
- IBTC taunts pick one random non-bot member from the IBTC role each time.
- The bot only selects non-bot users whose status is not `offline`.
- Users in `NEVER_PASS_USER_IDS` are excluded from daily BTGO winners and always fail `!inspect`.
- Users in `ALWAYS_PASS_USER_IDS` are always added to daily BTGO winners (when online) and always pass `!inspect`.
- Manual `!reshuffle` uses the guild where the command is invoked.
- If startup warns that `PyNaCl` is not installed, that only affects voice support and can be ignored for this bot.
