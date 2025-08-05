# SGP Bot Management Commands

# Show all available commands
default:
    @just --list

# Build the Docker image
build:
    docker-compose build

# Start the bot (detached)
up:
    docker-compose up -d

# Stop the bot
down:
    docker-compose down

# Restart the bot
restart:
    docker-compose restart

# Rebuild and restart the bot
rebuild:
    docker-compose down
    docker-compose build
    docker-compose up -d

# View live logs
logs:
    docker-compose logs -f sgp-bot

# View recent logs (last 100 lines)
logs-recent:
    docker-compose logs --tail=100 sgp-bot

# Check bot status
status:
    docker-compose ps

# Run the bot in foreground (for debugging)
run:
    docker-compose up

# Run the bot with debug logging
debug:
    docker-compose run --rm sgp-bot uv run python bot.py --debug

# Shell into the running container
shell:
    docker-compose exec sgp-bot /bin/bash

# Test the bot parsing logic locally (not in container)
test:
    uv run python -c "
    from bot import extract_command_text
    print('Testing /post command:', extract_command_text('/post Hello world!', 'post'))
    print('Testing /echo command:', extract_command_text('/echo Test message', 'echo'))
    "

# Clean up containers and images
clean:
    docker-compose down
    docker image prune -f
    docker system prune -f

# Complete cleanup (removes everything)
clean-all:
    docker-compose down -v --rmi all
    docker system prune -af

# Check if signal-cli socket is available
check-signal:
    @echo "Checking signal-cli socket..."
    @if [ -S "/run/user/1000/signal-cli/socket" ]; then \
        echo "✓ Signal socket found at /run/user/1000/signal-cli/socket"; \
    else \
        echo "✗ Signal socket not found. Make sure signal-cli daemon is running:"; \
        echo "  signal-cli -a +YOUR_NUMBER daemon --socket"; \
    fi

# Show environment variables (without sensitive values)
show-env:
    @echo "Environment configuration:"
    @echo "SIGNAL_ACCOUNT: $(grep SIGNAL_ACCOUNT .env | cut -d= -f2)"
    @echo "SIGNAL_GROUP: $(grep SIGNAL_GROUP .env | cut -d= -f2 | cut -c1-10)..."
    @echo "BSKY_USER: $(grep BSKY_USER .env | cut -d= -f2)"
    @echo "SIGNAL_SOCKET_PATH: $(grep SIGNAL_SOCKET_PATH .env | cut -d= -f2)"