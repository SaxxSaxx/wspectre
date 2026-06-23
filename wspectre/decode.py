"""Best-effort decoding of websocket frame payloads.

A frame's bytes rarely announce what they are. classify() walks the most
common encodings an app reaches for — json, msgpack, gzip, base64, utf-8 —
and tells you which one fits, plus a readable rendering.
"""
import base64
import binascii
import gzip
import json
import re

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

try:  # optional — msgpack detection is a bonus, not a dependency
    import msgpack
except Exception:  # pragma: no cover
    msgpack = None


def _is_json(s):
    s = s.strip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _pretty_json(s):
    return json.dumps(json.loads(s), indent=2, ensure_ascii=False)


def _b64_meaningful(s):
    """Decode `s` as base64 only if the result looks like real content.

    Base64 is itself valid text, so naive detection misfires on ordinary
    words. We require a clean round-trip to printable utf-8 that actually
    reads as structured or sentence-like data.
    """
    if len(s) < 8 or len(s) % 4 != 0 or not _B64_RE.match(s):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(raw).decode() != s:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():
        return None
    meaningful = (
        " " in text
        or _is_json(text)
        or (len(text) >= 12 and sum(c.isalnum() or c.isspace() for c in text) / len(text) > 0.85)
    )
    return text if meaningful else None


def _classify_text(s):
    if _is_json(s):
        return ("json", _pretty_json(s))
    b64 = _b64_meaningful(s)
    if b64 is not None:
        return ("base64", b64)
    return ("text", s)


def classify(data, is_text):
    """Return (kind, rendered_text) for a payload.

    `data` is bytes (or str); `is_text` is the frame's text/binary flag.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    if is_text:
        return _classify_text(data.decode("utf-8", "replace"))

    if data[:2] == b"\x1f\x8b":
        try:
            kind, rendered = classify(gzip.decompress(data), False)
            return ("gzip>" + kind, rendered)
        except Exception:
            pass

    if msgpack is not None:
        try:
            obj = msgpack.unpackb(data, raw=False)
            if isinstance(obj, (dict, list)):
                return ("msgpack", json.dumps(obj, indent=2, default=str, ensure_ascii=False))
        except Exception:
            pass

    try:
        s = data.decode("utf-8")
        if s.isprintable():
            return _classify_text(s)
    except UnicodeDecodeError:
        pass

    return ("binary", data.hex(" "))
