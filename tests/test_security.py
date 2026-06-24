"""Hostile-input hardening: payloads come from an untrusted peer."""
import gzip

import pytest

from wspectre.decode import MAX_DECODE_BYTES, classify


def test_gzip_bomb_is_bounded():
    # ~8 MiB of zeros compresses to a few KB; inflating must not exceed the cap.
    bomb = gzip.compress(b"\x00" * (8 * 1024 * 1024))
    assert len(bomb) < MAX_DECODE_BYTES
    kind, rendered = classify(bomb, False)
    assert kind == "binary"                 # refused to inflate past the limit
    assert len(rendered) < MAX_DECODE_BYTES


def test_gzip_within_limit_still_decodes():
    blob = gzip.compress(b'{"ok":true}')
    assert classify(blob, False)[0] == "gzip>json"


def test_msgpack_bogus_huge_array_is_safe():
    msgpack = pytest.importorskip("msgpack")
    # array32 header declaring ~4.2 billion elements, with no payload.
    blob = b"\xdd\xff\xff\xff\xff"
    kind, _ = classify(blob, False)
    assert kind == "binary"                 # rejected, never pre-allocated


def test_terminal_escape_in_text_is_neutralized():
    s = "\x1b]0;owned\x07 done\x1b[2J"       # OSC title hijack + clear-screen
    kind, rendered = classify(s, True)
    assert kind == "text"
    assert "\x1b" not in rendered and "\x07" not in rendered
    assert "\\x1b" in rendered


def test_json_c1_control_is_escaped():
    csi = chr(0x9B)                          # C1 Control Sequence Introducer
    kind, rendered = classify('{"x":"a' + csi + 'b"}', True)
    assert kind == "json"
    assert csi not in rendered               # ensure_ascii escaped it
    assert "\\u009b" in rendered
