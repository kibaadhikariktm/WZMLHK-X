import re
from contextlib import suppress
from PIL import Image
from hashlib import md5
from aiofiles.os import remove, path as aiopath, makedirs
import json
from asyncio import (
    create_subprocess_exec,
    gather,
    wait_for,
    sleep,
)
from asyncio.subprocess import PIPE
from os import path as ospath
from re import search as re_search, escape
from time import time
from aioshutil import rmtree
from langcodes import Language

from ... import LOGGER, DOWNLOAD_DIR, threads, cores
from ...core.config_manager import BinConfig
from .bot_utils import cmd_exec, sync_to_async
from .files_utils import get_mime_type, is_archive, is_archive_split
from .status_utils import time_to_seconds


def get_md5_hash(up_path):
    md5_hash = md5()
    with open(up_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
        return md5_hash.hexdigest()


async def create_thumb(msg, _id=""):
    if not _id:
        _id = time()
        path = f"{DOWNLOAD_DIR}thumbnails"
    else:
        path = "thumbnails"
    await makedirs(path, exist_ok=True)
    photo_dir = await msg.download()
    output = ospath.join(path, f"{_id}.jpg")

    def _convert_image(src, dst):
        with Image.open(src) as im:
            im.convert("RGB").save(dst, "JPEG", quality=95)

    await sync_to_async(_convert_image, photo_dir, output)
    await remove(photo_dir)
    return output


async def download_image_thumb(url):
    """Download an image from a URL and save it as a JPEG thumbnail.

    Validates that the URL points to an image via Content-Type header check.
    Returns the path to the saved thumbnail, or empty string on failure.
    """
    from httpx import AsyncClient

    # Content types that are definitely NOT images
    NON_IMAGE_TYPES = (
        "text/",
        "application/json",
        "application/xml",
        "application/javascript",
        "video/",
        "audio/",
    )
    try:
        async with AsyncClient(
            verify=False, follow_redirects=True, timeout=30
        ) as client:
            # HEAD request to check content type and size
            try:
                head_resp = await client.head(url)
                content_type = head_resp.headers.get("content-type", "")
                if content_type and any(
                    content_type.startswith(t) for t in NON_IMAGE_TYPES
                ):
                    LOGGER.error(f"Thumb URL is not an image: {content_type}")
                    return ""

            except Exception:
                pass  # HEAD failed, will check during GET

            # Download the image
            resp = await client.get(url)
            if resp.status_code != 200:
                LOGGER.error(f"Failed to download thumb URL: HTTP {resp.status_code}")
                return ""

            # Only reject known non-image types; unknown types are allowed
            # PIL will validate the actual image data below
            content_type = resp.headers.get("content-type", "")
            if content_type and any(
                content_type.startswith(t) for t in NON_IMAGE_TYPES
            ):
                LOGGER.error(f"Thumb URL is not an image: {content_type}")
                return ""

            data = resp.content

            # Save and convert to JPEG
            path = f"{DOWNLOAD_DIR}thumbnails"
            await makedirs(path, exist_ok=True)
            tmp_path = ospath.join(path, f"{time()}_tmp")
            with open(tmp_path, "wb") as f:
                f.write(data)
            output = ospath.join(path, f"{time()}.jpg")

            def _process_thumb(src, dst):
                with Image.open(src) as im:
                    im.convert("RGB").save(dst, "JPEG", quality=95)

            try:
                await sync_to_async(_process_thumb, tmp_path, output)
            except Exception as e:
                LOGGER.error(f"Failed to process thumb image: {e}")
                with suppress(Exception):
                    await remove(tmp_path)
                return ""
            with suppress(Exception):
                await remove(tmp_path)
            return output
    except Exception as e:
        LOGGER.error(f"Error downloading thumb from URL: {e}")
