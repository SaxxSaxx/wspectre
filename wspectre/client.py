"""Live websocket capture.

A thin async wrapper around the `websockets` client. Note: protocol-level
ping/pong is handled inside the library, so what you capture here is the
*application's* frames — which is exactly the layer worth reversing.
"""
import asyncio
import time

from .capture import Frame


async def _run(url, headers=None, origin=None, subprotocols=None, sends=None, duration=None):
    from websockets.asyncio.client import connect  # imported late so tests don't need network

    frames = []
    start = time.monotonic()
    now = lambda: round(time.monotonic() - start, 6)

    async with connect(
        url,
        additional_headers=headers or None,
        origin=origin,
        subprotocols=subprotocols,
    ) as ws:
        for msg in sends or []:
            await ws.send(msg)
            frames.append(Frame(now(), "up", "text", msg.encode("utf-8"), True))

        while True:
            remaining = None
            if duration is not None:
                remaining = duration - (time.monotonic() - start)
                if remaining <= 0:
                    break
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            except Exception:
                break
            is_text = isinstance(msg, str)
            data = msg.encode("utf-8") if is_text else msg
            frames.append(Frame(now(), "down", "text" if is_text else "binary", data, is_text))

    return frames


def listen(url, **kw):
    """Connect, optionally send seed frames, capture what comes back."""
    return asyncio.run(_run(url, **kw))
