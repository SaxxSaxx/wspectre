"""Capture model: frames in, JSONL out, structural diff.

The reverse-engineer's core move is comparison: capture state A, capture
state B, and the difference between them is usually the whole protocol.
diff() reduces each capture to a multiset of frame *signatures* and reports
what appeared and what vanished.
"""
import base64
import json
from collections import Counter
from dataclasses import dataclass

from .decode import classify


def _size_bucket(n):
    if n == 0:
        return "0"
    for e in (16, 64, 256, 1024, 4096, 16384):
        if n <= e:
            return f"<={e}"
    return ">16384"


@dataclass
class Frame:
    ts: float          # seconds since capture start
    direction: str     # "up" (sent) | "down" (received)
    opcode: str        # "text" | "binary" | "ping" | "pong" | "close"
    data: bytes
    is_text: bool

    def kind(self):
        if self.opcode in ("ping", "pong", "close"):
            return self.opcode
        return classify(self.data, self.is_text)[0]

    def signature(self):
        return (self.direction, self.kind(), _size_bucket(len(self.data)))


def to_jsonl(frames):
    rows = [
        json.dumps({
            "ts": f.ts, "dir": f.direction, "op": f.opcode,
            "text": f.is_text, "data": base64.b64encode(f.data).decode(),
        })
        for f in frames
    ]
    return "\n".join(rows) + ("\n" if rows else "")


def from_jsonl(text):
    frames = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        frames.append(Frame(
            ts=o["ts"], direction=o["dir"], opcode=o["op"],
            data=base64.b64decode(o["data"]), is_text=o["text"],
        ))
    return frames


def diff(a, b):
    """Signature-multiset diff: what's in `b` but not `a`, and vice versa."""
    ca = Counter(f.signature() for f in a)
    cb = Counter(f.signature() for f in b)
    return {
        "added": sorted((cb - ca).elements()),
        "removed": sorted((ca - cb).elements()),
    }
