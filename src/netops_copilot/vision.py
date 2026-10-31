"""Images attached to a request: a whiteboard photo, a ticket screenshot, a network diagram.

Muse Spark reads the image and writes a plain-language request; that request then goes through
the normal pipeline (schema, gate, dry-run, approval). Text inside an image is treated as data,
never as instructions: nothing the image says can skip a deterministic check.
"""

import base64
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024
MAX_IMAGES = 3
# The file type is decided from the bytes, not from the name or what the client claims.
SIGNATURES = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg"}
DEMO_KEY = "netops:request"  # PNG text chunk read by the offline model (see llm/mock.py)


class ImageError(ValueError):
    pass


@dataclass(frozen=True)
class Image:
    data: bytes
    mime: str
    name: str = "image"

    @property
    def data_url(self) -> str:
        return f"data:{self.mime};base64,{base64.b64encode(self.data).decode()}"


def _mime(data: bytes) -> str | None:
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return next((m for sig, m in SIGNATURES.items() if data.startswith(sig)), None)


def load(data: bytes, name: str = "image") -> Image:
    if not data:
        raise ImageError(f"{name}: empty file")
    if len(data) > MAX_BYTES:
        raise ImageError(f"{name}: {len(data) // 1024} KB, the limit is {MAX_BYTES // 1024} KB")
    mime = _mime(data)
    if mime is None:
        raise ImageError(f"{name}: not a PNG, JPEG or WebP image")
    return Image(data=data, mime=mime, name=name)


def load_path(path: str | Path) -> Image:
    path = Path(path)
    return load(path.read_bytes(), path.name)


def check_count(images: list[Image]) -> list[Image]:
    if len(images) > MAX_IMAGES:
        raise ImageError(f"{len(images)} images attached, the limit is {MAX_IMAGES}")
    return images


def content(text: str, images: list[Image]) -> list[dict]:
    """OpenAI-compatible multimodal message content: one text part, then the images."""
    return [{"type": "text", "text": text},
            *({"type": "image_url", "image_url": {"url": i.data_url}} for i in images)]


# ---- PNG text chunks: lets sample images carry their expected reading for offline demos ----

def png_text(data: bytes) -> dict[str, str]:
    chunks, pos = {}, 8
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if kind == b"tEXt" and b"\x00" in body:
            key, value = body.split(b"\x00", 1)
            chunks[key.decode("latin-1")] = value.decode("latin-1")
        pos += 12 + length
    return chunks


def with_png_text(data: bytes, key: str, value: str) -> bytes:
    """Insert a tEXt chunk right after IHDR."""
    body = key.encode("latin-1") + b"\x00" + value.encode("latin-1")
    chunk = struct.pack(">I", len(body)) + b"tEXt" + body
    chunk += struct.pack(">I", zlib.crc32(b"tEXt" + body) & 0xFFFFFFFF)
    ihdr_end = 8 + 12 + struct.unpack(">I", data[8:12])[0]
    return data[:ihdr_end] + chunk + data[ihdr_end:]
