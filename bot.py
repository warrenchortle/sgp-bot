#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Signal to Bluesky Bot - Listens for /post commands and posts to Bluesky
"""

import json
import socket
import os
import sys
import logging
import uuid
import re
from dotenv import load_dotenv
from atproto import Client

# Load environment variables
load_dotenv()

# Global configuration from environment variables
SIGNAL_ACCOUNT = os.getenv("SIGNAL_ACCOUNT")
SIGNAL_SOCKET_PATH = os.getenv("SIGNAL_SOCKET_PATH", "/run/user/1000/signal-cli/socket")
SIGNAL_GROUP = os.getenv("SIGNAL_GROUP")
BSKY_USER = os.getenv("BSKY_USER")
BSKY_PASS = os.getenv("BSKY_PASS")


def validate_environment():
    """Validate that all required environment variables are set"""
    required_vars = {
        "SIGNAL_ACCOUNT": SIGNAL_ACCOUNT,
        "SIGNAL_SOCKET_PATH": SIGNAL_SOCKET_PATH,
        "SIGNAL_GROUP": SIGNAL_GROUP,
        "BSKY_USER": BSKY_USER,
        "BSKY_PASS": BSKY_PASS,
    }

    missing = []
    for var_name, var_value in required_vars.items():
        if not var_value:
            missing.append(var_name)

    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            "Please set these in your .env file."
        )


def setup_logging(debug=False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    format_str = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=level, format=format_str, datefmt="%H:%M:%S")


def init_bluesky_client():
    """Initialize and authenticate Bluesky client"""
    try:
        client = Client()
        client.login(BSKY_USER, BSKY_PASS)
        logging.info(f"Successfully authenticated with Bluesky as {BSKY_USER}")
        return client
    except Exception as e:
        logging.error(f"Failed to authenticate with Bluesky: {e}")
        return None


def post_to_bluesky(client, text):
    """Post text to Bluesky"""
    try:
        client.send_post(text=text)
        logging.info(f"Successfully posted to Bluesky: {text[:50]}...")
        return True
    except Exception as e:
        logging.error(f"Failed to post to Bluesky: {e}")
        return False


def send_signal_message(group_id, message):
    """Send message to Signal group"""
    req_id = str(uuid.uuid4())

    frame = {
        "jsonrpc": "2.0",
        "method": "send",
        "params": {
            "account": SIGNAL_ACCOUNT,
            "groupId": group_id,
            "message": message,
        },
        "id": req_id,
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(SIGNAL_SOCKET_PATH)
            s.sendall((json.dumps(frame) + "\n").encode())

            # Read response
            buf = b""
            while not buf.endswith(b"\n"):
                buf += s.recv(1024)

        reply = json.loads(buf)
        if reply.get("id") != req_id:
            raise RuntimeError("Mismatching JSON-RPC id")
        if "error" in reply:
            raise RuntimeError(f"Signal error: {reply['error']}")

        logging.info(f"Sent message to Signal group: {group_id}")
        return True

    except Exception as e:
        logging.error(f"Failed to send Signal message: {e}")
        return False


def parse_signal_message(message_data):
    """Parse incoming Signal JSON-RPC message"""
    try:
        # Only process 'receive' method messages
        if message_data.get("method") != "receive":
            logging.debug(f"Ignoring non-receive message: {message_data.get('method')}")
            return None

        envelope = message_data.get("params", {}).get("envelope", {})

        # Only process dataMessage (ignore typingMessage, etc.)
        if "dataMessage" not in envelope:
            logging.debug(
                f"Ignoring message without dataMessage: {list(envelope.keys())}"
            )
            return None

        data_message = envelope["dataMessage"]

        # Skip messages without text content (reactions, etc.)
        message_content = data_message.get("message")
        if not message_content:
            logging.debug("Ignoring message without text content")
            return None

        # Extract relevant fields
        parsed = {
            "timestamp": envelope.get("timestamp"),
            "source_uuid": envelope.get("sourceUuid"),
            "source_name": envelope.get("sourceName"),
            "message": message_content,
            "group_id": None,
            "is_group": False,
        }

        # Check if it's a group message
        group_info = data_message.get("groupInfo")
        if group_info:
            parsed["group_id"] = group_info.get("groupId")
            parsed["is_group"] = True

        logging.debug(f"Parsed message: {parsed}")
        return parsed

    except Exception as e:
        logging.error(f"Error parsing message: {e}")
        logging.debug(f"Raw message data: {message_data}")
        return None


def extract_command_text(message, command):
    """Extract text from a command like /post or /echo"""
    # Pattern: /<command> <text>
    pattern = rf"^/{command}\s+(.+)$"
    match = re.match(pattern, message.strip(), re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def listen_for_posts():
    """Listen continuously for Signal messages and detect /post commands"""

    # Initialize Bluesky client
    bluesky_client = init_bluesky_client()
    if not bluesky_client:
        logging.error("Failed to initialize Bluesky client. Exiting.")
        sys.exit(1)

    logging.info("Signal to Bluesky Bot starting up...")
    logging.info(f"Listening for /post commands from group: {SIGNAL_GROUP}")
    logging.info(f"Connected to {SIGNAL_SOCKET_PATH}")
    logging.info(f"Posting to Bluesky as: {BSKY_USER}")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(SIGNAL_SOCKET_PATH)
            s.settimeout(1.0)  # 1 second timeout for non-blocking reads

            buffer = b""

            while True:
                try:
                    # Read data from socket
                    data = s.recv(1024)
                    if not data:
                        logging.warning("Socket closed by server")
                        break

                    buffer += data

                    # Process complete JSON lines
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line.strip():
                            try:
                                message_data = json.loads(line.decode("utf-8"))
                                logging.debug(f"Raw JSON received: {message_data}")

                                # Parse the message
                                parsed = parse_signal_message(message_data)
                                if not parsed:
                                    continue

                                # Check if message is from the target group
                                if not (
                                    parsed["is_group"]
                                    and parsed["group_id"] == SIGNAL_GROUP
                                ):
                                    logging.debug(
                                        f"Ignoring message from different group/DM: {parsed.get('group_id', 'DM')}"
                                    )
                                    continue

                                # Check if message starts with /post or /echo
                                post_text = extract_command_text(parsed["message"], "post")
                                echo_text = extract_command_text(parsed["message"], "echo")
                                
                                if post_text:
                                    logging.info("DETECTED /post command")
                                    logging.info(
                                        f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                    )
                                    logging.info(f"Post text: {post_text}")

                                    # Send confirmation to Signal
                                    send_signal_message(
                                        SIGNAL_GROUP, "Posting to Bluesky..."
                                    )

                                    # Post to Bluesky
                                    if post_to_bluesky(bluesky_client, post_text):
                                        send_signal_message(
                                            SIGNAL_GROUP,
                                            "Posted to Bluesky successfully!",
                                        )
                                        logging.info(
                                            "Successfully posted to Bluesky and confirmed in Signal"
                                        )
                                    else:
                                        send_signal_message(
                                            SIGNAL_GROUP, "L Failed to post to Bluesky"
                                        )
                                        logging.error("Failed to post to Bluesky")
                                
                                elif echo_text:
                                    logging.info("DETECTED /echo command")
                                    logging.info(
                                        f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                    )
                                    logging.info(f"Echo text: {echo_text}")

                                    # Echo the text back to Signal
                                    send_signal_message(SIGNAL_GROUP, echo_text)
                                    logging.info("Echoed message back to Signal")

                            except json.JSONDecodeError as e:
                                logging.error(f"Invalid JSON received: {line}")
                                logging.error(f"JSON Error: {e}")

                except socket.timeout:
                    # No data received, continue listening
                    continue
                except KeyboardInterrupt:
                    logging.info("Bot shutting down...")
                    break

    except ConnectionRefusedError:
        logging.error(f"Could not connect to socket at {SIGNAL_SOCKET_PATH}")
        logging.error(
            f"Make sure signal-cli daemon is running with: signal-cli -a {SIGNAL_ACCOUNT} daemon --socket"
        )
    except Exception as e:
        logging.error(f"Unexpected error: {e}")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Signal to Bluesky Bot")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(debug=args.debug)

    # Validate environment before starting
    try:
        validate_environment()
    except EnvironmentError as e:
        logging.error(str(e))
        sys.exit(1)

    listen_for_posts()


if __name__ == "__main__":
    main()

