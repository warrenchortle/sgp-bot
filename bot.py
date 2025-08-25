#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Signal to Bluesky Bot - Listens for /post commands and posts to Bluesky
"""

import json
import base64
import socket
import os
import sys
import logging
import uuid
import re
import io
from dotenv import load_dotenv
from atproto import Client
from PIL import Image, ImageOps
from typing import List

# Load environment variables
load_dotenv()

# Global configuration from environment variables
SIGNAL_ACCOUNT = os.getenv("SIGNAL_ACCOUNT")
SIGNAL_SOCKET_PATH = os.getenv("SIGNAL_SOCKET_PATH", "/run/user/1000/signal-cli/socket")
SIGNAL_GROUP = os.getenv("SIGNAL_GROUP")
BSKY_USER = os.getenv("BSKY_USER")
BSKY_PASS = os.getenv("BSKY_PASS")
REDACT_WORDS_ENV = os.getenv("REDACT_WORDS", "")

# Attachment handling configuration
MAX_IMAGES_PER_POST = 4
MAX_ATTACHMENT_SIZE_BYTES = 15 * 1024 * 1024  # 15MB per image - our limit
BLUESKY_MAX_SIZE_BYTES = 976 * 1024  # 976KB - Bluesky's limit
ALLOWED_IMAGE_MIME = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
}

# Cap for longest side when downscaling for Bluesky
MAX_IMAGE_DIMENSION = 2048


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


def post_to_bluesky(client, text, images=None):
    """Post to Bluesky and return post URL. If images is provided (list of bytes), include them."""
    try:
        if images and len(images) > 0:
            # Limit to MAX_IMAGES_PER_POST
            images = images[:MAX_IMAGES_PER_POST]
            response = client.send_images(text=text, images=images)
        else:
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


def _get_signal_rpc_reply(frame):
    """Send a JSON-RPC frame to signal-cli socket and return parsed reply."""
    req_id = frame.get("id")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SIGNAL_SOCKET_PATH)
        s.sendall((json.dumps(frame) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
    reply = json.loads(buf)
    if req_id is not None and reply.get("id") != req_id:
        raise RuntimeError("Mismatching JSON-RPC id")
    if "error" in reply:
        raise RuntimeError(f"Signal error: {reply['error']}")
    return reply


def get_signal_attachment(attachment_id, group_id=None, recipient=None):
    """Fetch an attachment via signal-cli getAttachment. Returns dict with content_type, data_b64, filename (optional)."""
    req_id = str(uuid.uuid4())
    params = {
        "account": SIGNAL_ACCOUNT,
        "id": attachment_id,
    }
    if group_id:
        params["groupId"] = group_id
    elif recipient:
        params["recipient"] = recipient

    frame = {
        "jsonrpc": "2.0",
        "method": "getAttachment",
        "params": params,
        "id": req_id,
    }

    reply = _get_signal_rpc_reply(frame)

    # getAttachment response shape may vary; try common keys
    result = reply.get("result", reply)
    content_type = (
        result.get("contentType")
        or result.get("content_type")
        or result.get("attachment", {}).get("contentType")
    )
    data_b64 = (
        result.get("data")
        or result.get("base64")
        or result.get("attachment", {}).get("data")
    )
    filename = result.get("filename") or result.get("attachment", {}).get("filename")

    if not data_b64:
        raise RuntimeError("getAttachment returned no data")

    return {
        "content_type": content_type,
        "data_b64": data_b64,
        "filename": filename,
    }


def _shrink_image_for_bluesky(image_bytes: bytes, mime: str | None = None) -> bytes:
    """Resize/re-encode an image to be under Bluesky's blob size limit.

    Strategy:
    - Apply EXIF transpose to correct orientation.
    - Convert to RGB and flatten alpha.
    - Try JPEG re-encoding at several qualities; if still too large, iteratively downscale.

    Returns the best-effort smaller bytes; returns original bytes on failure.
    """
    try:
        if len(image_bytes) <= BLUESKY_MAX_SIZE_BYTES:
            return image_bytes

        with Image.open(io.BytesIO(image_bytes)) as im:
            # Normalize orientation
            try:
                im = ImageOps.exif_transpose(im)
            except Exception:
                pass

            # Convert to RGB and flatten any alpha
            if im.mode in ("RGBA", "LA"):
                bg = Image.new("RGB", im.size, (255, 255, 255))
                bg.paste(im, mask=im.split()[-1])
                im = bg
            elif im.mode not in ("RGB", "L"):
                im = im.convert("RGB")

            def encode(img: Image.Image, quality: int) -> bytes:
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=quality, optimize=True, progressive=True)
                return buf.getvalue()

            def resize_longest(img: Image.Image, target_longest: int) -> Image.Image:
                w, h = img.size
                longest = max(w, h)
                if longest <= target_longest:
                    return img
                scale = target_longest / float(longest)
                new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
                return img.resize(new_size, Image.LANCZOS)

            # First attempt: keep resolution, lower quality a bit
            for q in (85, 80, 75):
                data = encode(im, q)
                if len(data) <= BLUESKY_MAX_SIZE_BYTES:
                    return data

            # Iteratively downscale and re-encode
            longest_targets = [MAX_IMAGE_DIMENSION, 1600, 1280, 1080, 960, 800, 720, 640]
            quality_steps = [75, 70, 65, 60, 55, 50, 45, 40]

            best_bytes = image_bytes
            best_size = len(image_bytes)

            work = im
            for target in longest_targets:
                work = resize_longest(work, target)
                for q in quality_steps:
                    data = encode(work, q)
                    if len(data) < best_size:
                        best_bytes, best_size = data, len(data)
                    if len(data) <= BLUESKY_MAX_SIZE_BYTES:
                        return data

            return best_bytes
    except Exception:
        return image_bytes


# ----- Redaction support -----
def _parse_redact_words(raw: str) -> List[str]:
    """Parse CSV redact words into a list (trimmed, no empties)."""
    if not raw:
        return []
    return [w.strip() for w in raw.split(",") if w.strip()]


_REDACT_WORDS: List[str] = _parse_redact_words(REDACT_WORDS_ENV)
_REDACT_PATTERN = (
    re.compile("|".join(re.escape(w) for w in _REDACT_WORDS), re.IGNORECASE)
    if _REDACT_WORDS
    else None
)


def redact_text(text: str) -> str:
    """Remove all case-insensitive occurrences of configured words from text."""
    if not text:
        return text
    if _REDACT_PATTERN is None:
        return text
    return _REDACT_PATTERN.sub("", text)


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
            "text": post.record.text[:50]
            + ("..." if len(post.record.text) > 50 else ""),
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


def send_signal_message(
    group_id,
    message,
    preview_url=None,
    preview_title=None,
    preview_description=None,
    preview_image=None,
):
    """Send message to Signal group. If preview fields are provided, include them."""
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

    if preview_url:
        # Include previewUrl to let Signal render a link preview
        frame["params"]["previewUrl"] = preview_url
    if preview_title:
        frame["params"]["previewTitle"] = preview_title
    if preview_description:
        frame["params"]["previewDescription"] = preview_description
    if preview_image:
        frame["params"]["previewImage"] = preview_image

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
            "source": envelope.get("source"),
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
            parsed["has_quote"] = (
                bool(parsed["quote_text"])
                if parsed.get("quote_text") is not None
                else False
            )
        else:
            parsed["has_quote"] = False

        # Check if it's a group message
        group_info = data_message.get("groupInfo")
        if group_info:
            parsed["group_id"] = group_info.get("groupId")
            parsed["is_group"] = True

        # Capture attachments metadata if present
        attachments = data_message.get("attachments") or []
        normalized = []
        for a in attachments:
            try:
                normalized.append(
                    {
                        "id": a.get("id"),
                        "contentType": a.get("contentType"),
                        "filename": a.get("filename"),
                    }
                )
            except Exception:
                continue
        parsed["attachments"] = normalized

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
                                is_post_cmd = (
                                    parsed["message"]
                                    .strip()
                                    .lower()
                                    .startswith("/post")
                                )
                                inline_post_text = extract_command_text(
                                    parsed["message"], "post"
                                )
                                quoted_text = parsed.get("quote_text")
                                final_post_text = None
                                if (
                                    quoted_text
                                    and isinstance(quoted_text, str)
                                    and quoted_text.strip()
                                ):
                                    final_post_text = quoted_text.strip()
                                elif inline_post_text and inline_post_text.strip():
                                    final_post_text = inline_post_text.strip()
                                delete_text = extract_command_text(
                                    parsed["message"], "delete"
                                )
                                # Check for /help command (with or without text)
                                help_text = None
                                if (
                                    parsed["message"]
                                    .strip()
                                    .lower()
                                    .startswith("/help")
                                ):
                                    help_text = (
                                        ""  # Set to empty string to trigger help
                                    )

                                echo_text = extract_command_text(
                                    parsed["message"], "echo"
                                )

                                if is_post_cmd:
                                    # Check if we have attachments (for image-only posts)
                                    has_attachments = bool(parsed.get("attachments")) and not parsed.get("has_quote")
                                    
                                    # Process if we have text OR attachments
                                    if final_post_text or has_attachments:
                                        logging.info("DETECTED /post command")
                                        logging.info(
                                            f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                        )
                                        if quoted_text and quoted_text.strip():
                                            logging.info("Using quoted text for /post")
                                        if final_post_text:
                                            logging.info(f"Post text: {final_post_text}")
                                        else:
                                            logging.info("No text - posting image(s) only")

                                        # Collect images if no quote and attachments are present
                                        images_bytes = []
                                        atts = []
                                        if not parsed.get("has_quote"):
                                            atts = parsed.get("attachments") or []
                                            if atts:
                                                logging.debug(
                                                    f"Found {len(atts)} attachment(s) in message"
                                                )
                                            for att in atts:
                                                if (
                                                    len(images_bytes)
                                                    >= MAX_IMAGES_PER_POST
                                                ):
                                                    break
                                                ctype = att.get("contentType")
                                                if ctype not in ALLOWED_IMAGE_MIME:
                                                    logging.debug(
                                                        f"Skipping non-image/unsupported type: {ctype}"
                                                    )
                                                    continue
                                                # Get attachment id - can be numeric or string
                                                raw_id = att.get("id")
                                                filename_hint = att.get("filename")

                                                # Accept both numeric and string attachment IDs
                                                if raw_id is not None:
                                                    att_id = raw_id
                                                else:
                                                    logging.debug(
                                                        f"Skipping attachment without id: {att}"
                                                    )
                                                    continue
                                                try:
                                                    # Try to fetch the attachment
                                                    fetched = get_signal_attachment(
                                                        att_id,
                                                        group_id=parsed.get("group_id"),
                                                        recipient=parsed.get("source"),
                                                    )
                                                    data_b64 = fetched.get("data_b64")
                                                    img_bytes = base64.b64decode(data_b64)
                                                    if (
                                                        len(img_bytes)
                                                        > MAX_ATTACHMENT_SIZE_BYTES
                                                    ):
                                                        logging.warning(
                                                            f"Attachment {att_id} too large, skipping"
                                                        )
                                                        continue
                                                    # Downscale/compress to fit Bluesky blob limit
                                                    processed = _shrink_image_for_bluesky(
                                                        img_bytes, ctype
                                                    )
                                                    if len(processed) > BLUESKY_MAX_SIZE_BYTES:
                                                        logging.warning(
                                                            f"Attachment {att_id} still exceeds Bluesky size after processing; skipping"
                                                        )
                                                        continue
                                                    images_bytes.append(processed)
                                                    logging.info(
                                                        f"Successfully fetched attachment: {att_id}"
                                                    )
                                                except Exception as e:
                                                    logging.warning(
                                                        f"Failed to fetch/process attachment id={att_id} filename={filename_hint}: {e}"
                                                    )
                                                    continue

                                        # Post to Bluesky with optional images
                                        # Redact text if configured; use empty string if only images
                                        post_text = redact_text(final_post_text) if final_post_text else ""
                                        result = post_to_bluesky(
                                            bluesky_client,
                                            post_text,
                                            images=images_bytes,
                                        )
                                        if result["success"]:
                                            url = result.get("url")
                                            if url:
                                                # Build preview title from env (full account name)
                                                title = BSKY_USER or ""
                                                if title and not title.startswith("@"):
                                                    title = f"@{title}"
                                                # Use the posted text as the preview description (or indicate image-only)
                                                description = post_text or "📷 Image"
                                                # Send only the URL and include preview fields for rich preview
                                                send_signal_message(
                                                    SIGNAL_GROUP,
                                                    url,
                                                    preview_url=url,
                                                    preview_title=title,
                                                    preview_description=description,
                                                )
                                            else:
                                                # Fallback if URL couldn't be derived
                                                send_signal_message(
                                                    SIGNAL_GROUP, "Posted to Bluesky"
                                                )
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
                                    else:
                                        # /post command without text or valid attachments
                                        send_signal_message(
                                            SIGNAL_GROUP,
                                            "L No content to post. Include text or images with your /post command.",
                                        )

                                elif delete_text:
                                    logging.info("DETECTED /delete command")
                                    logging.info(
                                        f"From: {parsed['source_name']} ({parsed['source_uuid']})"
                                    )

                                    # Check if it's "delete this" command
                                    if delete_text.strip().lower() == "this":
                                        logging.info(
                                            "Delete this - getting latest post"
                                        )

                                        # Get the latest post
                                        latest_result = get_latest_post(bluesky_client)
                                        if not latest_result["success"]:
                                            send_signal_message(
                                                SIGNAL_GROUP,
                                                f"L Failed to get latest post: {latest_result.get('error')}",
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
                                                f"L Failed to delete latest post: {result.get('error')}",
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
