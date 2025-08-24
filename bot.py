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


def at_uri_to_bsky_url(at_uri, handle=None):
    """Convert AT URI to bsky.app URL, optionally using handle instead of DID"""
    pattern = r"^at://([^/]+)/([^/]+)/([^/]+)$"
    match = re.match(pattern, at_uri)

    if not match:
        return None

    did, collection, rkey = match.groups()

    if collection == "app.bsky.feed.post":
        # Use handle if provided, otherwise use DID
        profile_id = handle if handle else did
        return f"https://bsky.app/profile/{profile_id}/post/{rkey}"
    else:
        return None


def bsky_url_to_at_uri(url):
    """Convert bsky.app URL back to AT URI"""
    # Pattern for https://bsky.app/profile/{handle_or_did}/post/{rkey}
    pattern = r"^https://bsky\.app/profile/([^/]+)/post/([^/]+)$"
    match = re.match(pattern, url)

    if not match:
        return None

    profile_id, rkey = match.groups()

    # If profile_id is a handle, we need to resolve it to a DID
    # For now, we'll construct the AT URI with what we have
    # The actual DID resolution would need to be done via the client
    return {
        "profile_id": profile_id,
        "rkey": rkey,
        "needs_resolution": not profile_id.startswith("did:"),
    }


def post_to_bluesky(client, text):
    """Post text to Bluesky and return post URL"""
    try:
        response = client.send_post(text=text)
        logging.info(f"Successfully posted to Bluesky: {text[:50]}...")

        # Convert AT URI to web URL using the handle from BSKY_USER
        # Extract just the username part (before .bsky.social if present)
        handle = BSKY_USER
        if not handle.endswith(".bsky.social"):
            handle = f"{handle}.bsky.social"

        post_url = at_uri_to_bsky_url(response.uri, handle)

        return {
            "success": True,
            "uri": response.uri,
            "cid": response.cid,
            "url": post_url,
        }
    except Exception as e:
        logging.error(f"Failed to post to Bluesky: {e}")
        return {"success": False, "error": str(e)}


def get_latest_post(client):
    """Get the most recent post from the authenticated user"""
    try:
        # Get the user's profile timeline (their posts)
        timeline = client.get_author_feed(client.me.did, limit=1)
        
        if not timeline.feed or len(timeline.feed) == 0:
            return {"success": False, "error": "No posts found"}
        
        post = timeline.feed[0].post
        
        # Convert AT URI to web URL using handle
        handle = BSKY_USER
        if not handle.endswith(".bsky.social"):
            handle = f"{handle}.bsky.social"
        
        post_url = at_uri_to_bsky_url(post.uri, handle)
        
        return {
            "success": True,
            "uri": post.uri,
            "cid": post.cid,
            "url": post_url,
            "text": post.record.text[:50] + ("..." if len(post.record.text) > 50 else "")
        }
        
    except Exception as e:
        logging.error(f"Failed to get latest post: {e}")
        return {"success": False, "error": str(e)}


def delete_bluesky_post(client, url):
    """Delete a Bluesky post given its URL"""
    try:
        # Parse the URL to extract components
        parsed = bsky_url_to_at_uri(url)
        if not parsed:
            return {"success": False, "error": "Invalid Bluesky URL format"}

        profile_id = parsed["profile_id"]
        rkey = parsed["rkey"]

        # If profile_id is a handle, we need to get the DID
        if parsed["needs_resolution"]:
            # Check if it's our own post (comparing handles)
            handle = profile_id
            if not handle.endswith(".bsky.social"):
                handle_check = f"{handle}.bsky.social"
            else:
                handle_check = handle

            user_handle = BSKY_USER
            if not user_handle.endswith(".bsky.social"):
                user_handle = f"{user_handle}.bsky.social"

            if handle_check.lower() != user_handle.lower():
                return {"success": False, "error": "Can only delete your own posts"}

            # Use the client's DID for deletion
            did = client.me.did
        else:
            # It's already a DID
            did = profile_id
            # Verify it's our own post
            if did != client.me.did:
                return {"success": False, "error": "Can only delete your own posts"}

        # Construct the AT URI
        at_uri = f"at://{did}/app.bsky.feed.post/{rkey}"

        # Delete the post
        client.delete_post(at_uri)
        logging.info(f"Successfully deleted post: {at_uri}")

        return {"success": True, "deleted_uri": at_uri}

    except Exception as e:
        logging.error(f"Failed to delete post: {e}")
        return {"success": False, "error": str(e)}


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

        # Detect and capture quote details if present
        quote = data_message.get("quote")
        if quote:
            parsed["quote_id"] = quote.get("id")
            parsed["quote_author"] = quote.get("author")
            parsed["quote_text"] = quote.get("text")
            parsed["has_quote"] = bool(parsed["quote_text"]) if parsed.get("quote_text") is not None else False
        else:
            parsed["has_quote"] = False

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

                                # Check if message starts with /post, /delete, /help, or /echo
                                # For /post: prefer quoted text if present
                                is_post_cmd = parsed["message"].strip().lower().startswith("/post")
                                inline_post_text = extract_command_text(
                                    parsed["message"], "post"
                                )
                                quoted_text = parsed.get("quote_text")
                                final_post_text = None
                                if quoted_text and isinstance(quoted_text, str) and quoted_text.strip():
                                    final_post_text = quoted_text.strip()
                                elif inline_post_text and inline_post_text.strip():
                                    final_post_text = inline_post_text.strip()
                                delete_text = extract_command_text(
                                    parsed["message"], "delete"
                                )
                                # Check for /help command (with or without text)
                                help_text = None
                                if parsed["message"].strip().lower().startswith("/help"):
                                    help_text = ""  # Set to empty string to trigger help
                                
                                echo_text = extract_command_text(
                                    parsed["message"], "echo"
                                )

                                if is_post_cmd and final_post_text:
                                    logging.info("DETECTED /post command")
                                    logging.info(
                                        f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                    )
                                    if quoted_text and quoted_text.strip():
                                        logging.info("Using quoted text for /post")
                                    logging.info(f"Post text: {final_post_text}")

                                    # Post to Bluesky
                                    result = post_to_bluesky(bluesky_client, final_post_text)
                                    if result["success"]:
                                        message = "Posted to Bluesky"
                                        if result.get("url"):
                                            message += f"\n{result['url']}"
                                        send_signal_message(SIGNAL_GROUP, message)
                                        logging.info(
                                            f"Successfully posted to Bluesky and confirmed in Signal. URL: {result.get('url')}"
                                        )
                                    else:
                                        send_signal_message(
                                            SIGNAL_GROUP, "L Failed to post to Bluesky"
                                        )
                                        logging.error(
                                            f"Failed to post to Bluesky: {result.get('error')}"
                                        )
                                elif is_post_cmd and not final_post_text:
                                    # /post command without usable text or quote
                                    send_signal_message(
                                        SIGNAL_GROUP,
                                        "L No text to post. Reply with /post to a message or include text.",
                                    )

                                elif delete_text:
                                    logging.info("DETECTED /delete command")
                                    logging.info(
                                        f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                    )
                                    
                                    # Check if it's "delete this" command
                                    if delete_text.strip().lower() == "this":
                                        logging.info("Delete this - getting latest post")
                                        
                                        # Get the latest post
                                        latest_result = get_latest_post(bluesky_client)
                                        if not latest_result["success"]:
                                            send_signal_message(
                                                SIGNAL_GROUP,
                                                f"L Failed to get latest post: {latest_result.get('error')}"
                                            )
                                            continue
                                        
                                        # Delete the latest post using its URL
                                        result = delete_bluesky_post(
                                            bluesky_client, latest_result["url"]
                                        )
                                        
                                        if result["success"]:
                                            message = f"Deleted latest post from Bluesky\n{latest_result['url']}"
                                            send_signal_message(SIGNAL_GROUP, message)
                                            logging.info(
                                                f"Successfully deleted latest post: {result.get('deleted_uri')}"
                                            )
                                        else:
                                            send_signal_message(
                                                SIGNAL_GROUP,
                                                f"L Failed to delete latest post: {result.get('error')}"
                                            )
                                            logging.error(
                                                f"Failed to delete latest post: {result.get('error')}"
                                            )
                                    else:
                                        # Regular delete with URL
                                        logging.info(f"Delete URL: {delete_text}")
                                        
                                        result = delete_bluesky_post(
                                            bluesky_client, delete_text.strip()
                                        )
                                        if result["success"]:
                                            send_signal_message(
                                                SIGNAL_GROUP,
                                                "Post deleted from Bluesky",
                                            )
                                            logging.info(
                                                f"Successfully deleted post from Bluesky: {result.get('deleted_uri')}"
                                            )
                                        else:
                                            send_signal_message(
                                                SIGNAL_GROUP,
                                                f"L Failed to delete post: {result.get('error')}",
                                            )
                                            logging.error(
                                                f"Failed to delete post: {result.get('error')}"
                                            )

                                elif (
                                    help_text is not None
                                ):  # Use 'is not None' to handle empty help command
                                    logging.info("DETECTED /help command")
                                    help_message = """SGP Bot Commands:
/post <text> - Post to Bluesky
/delete <url> - Delete Bluesky post
/delete this - Delete latest post
/echo <text> - Echo text back
/help - Show this help"""
                                    send_signal_message(SIGNAL_GROUP, help_message)
                                    logging.info("Sent help message")

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
