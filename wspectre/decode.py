"""Best-effort decoding of websocket frame payloads.

A frame's bytes rarely announce what they are. classify() walks the most
common encodings an app reaches for — json, msgpack, gzip, base64, utf-8 —
and tells you which one fits, plus a readable rendering.
"""
import base64
import binascii
import json
import re
import zlib

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# Payloads arrive from an untrusted peer. Cap any amplifying decode so a hostile
# frame can't exhaust memory (decompression bombs, declared-huge containers).
MAX_DECODE_BYTES = 4 * 1024 * 1024


def _safe_gunzip(data, limit=MAX_DECODE_BYTES):
    """Bounded gzip inflate — returns None if the stream expands past `limit`."""
    dec = zlib.decompressobj(31)  # wbits=31 -> gzip framing
    try:
        out = dec.decompress(data, limit)
        if dec.unconsumed_tail:  # more output was waiting: treat as a bomb
            return None
        out += dec.flush()
    except zlib.error:
        return None
    return out if len(out) <= limit else None


def _sanitize_ctrl(text):
    """Escape terminal-control bytes so a payload can't drive the terminal.

    Keeps tab/newline and ordinary printable text; renders C0/C1/DEL controls
    (ESC, CSI, BEL, ...) as visible \\xNN so they're seen, not executed.
    """
    out = []
    for ch in text:
        o = ord(ch)
        if ch in "\t\n" or 0x20 <= o <= 0x7E or o >= 0xA0:
            out.append(ch)
        else:
            out.append(f"\\x{o:02x}")
    return "".join(out)

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
    # ensure_ascii=True escapes every non-ascii (incl. C1 controls) to \uNNNN,
    # so rendered json can't smuggle terminal escapes either.
    return json.dumps(json.loads(s), indent=2, ensure_ascii=True)


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
        return ("base64", _sanitize_ctrl(b64))
    return ("text", _sanitize_ctrl(s))


def classify(data, is_text):
    """Return (kind, rendered_text) for a payload.

    `data` is bytes (or str); `is_text` is the frame's text/binary flag.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    if is_text:
        return _classify_text(data.decode("utf-8", "replace"))

    if data[:2] == b"\x1f\x8b":
        inflated = _safe_gunzip(data)
        if inflated is not None:
            kind, rendered = classify(inflated, False)
            return ("gzip>" + kind, rendered)

    if msgpack is not None:
        try:
            # Bound every declared length to the actual buffer: a container can't
            # hold more elements than there are bytes, so this can't over-allocate.
            n = min(len(data), MAX_DECODE_BYTES)
            obj = msgpack.unpackb(
                data, raw=False, strict_map_key=False,
                max_str_len=n, max_bin_len=n, max_array_len=n, max_map_len=n, max_ext_len=n,
            )
            if isinstance(obj, (dict, list)):
                return ("msgpack", json.dumps(obj, indent=2, default=str, ensure_ascii=True))
        except Exception:
            pass

    try:
        s = data.decode("utf-8")
        if s.isprintable():
            return _classify_text(s)
    except UnicodeDecodeError:
        pass

    return ("binary", data.hex(" "))
