# Signal to Bluesky Bot

A bot that listens for `/post` commands in a Signal group and automatically posts the message to Bluesky.

## Features

- Listens to a specific Signal group for `/post` commands
- Automatically posts the message content to Bluesky
- Provides feedback in the Signal group about posting status
- Full error handling and logging

## Setup

### Prerequisites

- Python 3.8+
- `uv` package manager
- `signal-cli` installed and configured
- Bluesky account with app password

### Installation

1. Install dependencies:
```bash
uv sync
```

2. Create a `.env` file with your configuration:
```env
BSKY_USER=your-handle.bsky.social
BSKY_PASS=your-app-password
SIGNAL_ACCOUNT=+1234567890
SIGNAL_SOCKET_PATH=/run/user/1000/signal-cli/socket
SIGNAL_GROUP=your-group-id-here
```

### Configuration

#### Bluesky Setup
1. Go to Bluesky Settings → App Passwords
2. Create a new app password
3. Use your handle (e.g., `username.bsky.social`) and the app password in the `.env` file

#### Signal Setup
1. Install and configure `signal-cli`
2. Start the signal-cli daemon:
```bash
signal-cli -a +1234567890 daemon --socket
```
3. Get your group ID by monitoring signal-cli output or using the listGroups command

### Optional: Redaction

You can configure a list of words to be automatically removed from any text before it is posted to Bluesky (and from the Signal preview description).

- Env var: `REDACT_WORDS`
- Format: comma-separated values (CSV)
- Matching: case-insensitive, substring removal

Example `.env` line:

```env
REDACT_WORDS=alice,charlie,projectx
```

If omitted, no redaction is performed.

## Usage

### Running with Docker (Recommended)

The easiest way to run the bot is using Docker with the provided justfile commands:

```bash
# Build and start the bot
just build
just up

# View logs
just logs

# Stop the bot
just down

# Restart the bot
just restart
```

The bot will automatically restart unless manually stopped, so you can just set it and forget it.

### Available Commands

Use `just` to see all available commands:

```bash
just                 # Show all commands
just build          # Build the Docker image  
just up             # Start the bot (detached)
just down           # Stop the bot
just logs           # View live logs
just status         # Check bot status
just restart        # Restart the bot
just rebuild        # Rebuild and restart
just check-signal   # Verify signal-cli socket
just clean          # Clean up containers
```

### Running Locally (Development)

```bash
# Normal mode
uv run python bot.py

# Debug mode (verbose logging)
uv run python bot.py --debug
```

### Using the Bot

In your Signal group, send a message starting with `/post` followed by the text you want to post to Bluesky:

```
/post Hello world! This will be posted to Bluesky.
```

The bot will:
1. Detect the `/post` command
2. Post the text to Bluesky
3. Reply in Signal with only the Bluesky post URL (and a rich preview)

You can also reply with `/post` to any message in the group. If your `/post` message includes a quote (i.e., you replied to a message), the bot will ignore any text typed after `/post` and will post the quoted message's text instead.

### Examples

```
/post Just deployed a new feature! 🚀

/post Check out this cool project I'm working on:
https://github.com/username/project

/post Multi-line posts work too!
This is the second line.
And this is the third.

# Replying to a message with /post (quote handling)
# The bot will post the quoted message text, ignoring any inline text you add
# Example usage in Signal:
# 1) Reply to a message with just: /post
# 2) Reply to a message with: /post ignore this text
# In both cases, the quoted message content will be posted.
```

## Testing

Run the test suite to verify the bot logic:

```bash
uv run python test_bot.py
```

## Logging

The bot provides comprehensive logging:
- Info level: Shows successful operations and status updates
- Debug level: Shows detailed message parsing and API calls
- Error level: Shows failures and exceptions

## Security Notes

- Keep your `.env` file secure and never commit it to version control
- Use Bluesky app passwords instead of your main account password
- The bot only listens to the specific Signal group configured in `SIGNAL_GROUP`

## Troubleshooting

### "Could not connect to socket"
- Make sure `signal-cli` daemon is running
- Check that the socket path in `.env` matches your system
- Verify the Signal account number is correct

### "Failed to authenticate with Bluesky"
- Verify your Bluesky handle and app password are correct
- Check that your Bluesky account is in good standing
- Try creating a new app password

### Bot not responding to `/post` commands
- Check that the message is sent in the correct Signal group
- Verify the group ID in your `.env` file
- Run with `--debug` to see detailed message parsing logs
