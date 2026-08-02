"""Text normalisation and payload extraction.

Attackers rarely send ``ignore previous instructions`` verbatim -- they space
it out, swap Latin letters for Cyrillic look-alikes, hide it with zero-width
characters, or base64/hex-encode it. This module produces the cleaned views the
detectors match against, and pulls decoded payloads back out so hidden
instructions can be scanned too.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

from .types import Direction

# Zero-width / invisible formatting characters used to break up keywords.
_INVISIBLE = {
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,  # word joiner + invisible ops
    0xFEFF,  # BOM / ZWNBSP
}

# Common homoglyphs: characters that render like an ASCII letter but aren't.
# Folding them defeats "іgnore prevіous" (Cyrillic i) style evasion.
_HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Х": "X",
    "ο": "o",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "Ѕ": "S",
    "ѕ": "s",
    "Ї": "I",
    "ӏ": "l",
}

# Unicode "tag" block (U+E0000-U+E007F): invisible, but survives copy/paste and
# has been used to smuggle instructions past humans and naive filters alike.
_TAG_RANGE = range(0xE0000, 0xE0080)

_ZWSTRIP = str.maketrans({cp: None for cp in _INVISIBLE})
_FOLD = str.maketrans(_HOMOGLYPHS)

_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
MAX_ENCODED_TOKEN_CHARS = 65_536
MAX_DECODED_PAYLOADS = 16


def strip_invisibles(text: str) -> str:
    """Remove zero-width and unicode-tag characters."""
    text = text.translate(_ZWSTRIP)
    if any(ord(ch) in _TAG_RANGE for ch in text):
        text = "".join(ch for ch in text if ord(ch) not in _TAG_RANGE)
    return text


def has_invisibles(text: str) -> bool:
    return any(ord(ch) in _INVISIBLE or ord(ch) in _TAG_RANGE for ch in text)


def has_tag_chars(text: str) -> bool:
    return any(ord(ch) in _TAG_RANGE for ch in text)


def homoglyph_chars(text: str) -> List[str]:
    """Return the look-alike characters present, if any."""
    return [ch for ch in text if ch in _HOMOGLYPHS]


def fold(text: str) -> str:
    """Full normalisation used for keyword matching.

    NFKC, strip invisibles, fold homoglyphs, lowercase, then collapse runs of
    whitespace and punctuation so ``i-g-n-o-r-e`` and ``i g n o r e`` both land
    near ``ignore``.
    """
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisibles(text)
    text = text.translate(_FOLD)
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text


def _looks_textual(data: bytes) -> bool:
    """True if decoded bytes are mostly printable ASCII (i.e. a hidden message)."""
    if len(data) < 8:
        return False
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t ")
    return printable / len(s) >= 0.85 and any(c.isalpha() for c in s)


def decode_payloads(text: str) -> List[str]:
    """Extract and decode base64/hex blobs that turn out to be readable text.

    Only decoded segments that look like natural language are returned, so a
    random hash or an image data URI does not generate noise.
    """
    found: List[str] = []
    for match in _BASE64_TOKEN.finditer(text):
        token = match.group(0)
        if len(token) > MAX_ENCODED_TOKEN_CHARS:
            continue
        pad = "=" * (-len(token) % 4)
        try:
            data = base64.b64decode(token + pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _looks_textual(data):
            found.append(data.decode("utf-8"))
            if len(found) >= MAX_DECODED_PAYLOADS:
                return found
    for match in _HEX_TOKEN.finditer(text):
        token = match.group(0)
        if token.startswith("0x"):
            token = token[2:]
        if len(token) > MAX_ENCODED_TOKEN_CHARS:
            continue
        if len(token) % 2:
            continue
        try:
            data = bytes.fromhex(token)
        except ValueError:
            continue
        if _looks_textual(data):
            found.append(data.decode("utf-8"))
            if len(found) >= MAX_DECODED_PAYLOADS:
                return found
    return found


@dataclass
class ScanContext:
    """Pre-computed views of the text, shared by every detector in one scan.

    Building these once keeps a scan from normalising and base64-decoding the
    same string inside every detector.
    """

    raw: str
    direction: Direction = Direction.INPUT
    folded: str = ""
    decoded: List[str] = field(default_factory=list)

    @classmethod
    def build(cls, text: str, direction: Direction = Direction.INPUT) -> ScanContext:
        return cls(
            raw=text,
            direction=direction,
            folded=fold(text),
            decoded=decode_payloads(text),
        )

    def searchable(self) -> List[str]:
        """The folded text plus a folded view of every decoded payload."""
        return [self.folded] + [fold(d) for d in self.decoded]
