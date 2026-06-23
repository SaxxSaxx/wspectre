"""wspectre command line."""
import argparse
import sys

from .capture import diff, from_jsonl, to_jsonl
from .decode import classify
from .timing import detect_heartbeat

ARROW = {"up": "↑", "down": "↓"}


def _render(frames):
    lines = []
    for f in frames:
        if f.opcode in ("ping", "pong", "close"):
            kind, rendered = f.opcode, ""
        else:
            kind, rendered = classify(f.data, f.is_text)
        head = " ".join(rendered.split()) if rendered else ""
        if len(head) > 72:
            head = head[:71] + "…"
        lines.append(f"{ARROW.get(f.direction, '?')} {f.ts:8.3f}  {kind:12} {head}")
    out = "\n".join(lines)

    downs = [f.ts for f in frames if f.direction == "down"]
    hb = detect_heartbeat(downs) if len(downs) >= 4 else None
    if hb:
        out += f"\n\nheartbeat: {hb['period']}s ×{hb['count']}  (confidence {hb['confidence']})"
    return out


def _build_parser():
    p = argparse.ArgumentParser(prog="wspectre", description="hear what the wire is really saying")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("listen", help="connect and capture frames")
    pl.add_argument("url")
    pl.add_argument("-H", "--header", action="append", default=[], metavar="K:V")
    pl.add_argument("--origin")
    pl.add_argument("--subprotocol", action="append", default=[])
    pl.add_argument("--send", action="append", default=[], metavar="MSG")
    pl.add_argument("--duration", type=float, default=None, metavar="SECONDS")
    pl.add_argument("--save", metavar="FILE")

    ps = sub.add_parser("show", help="render a saved capture")
    ps.add_argument("file")

    pd = sub.add_parser("diff", help="compare two captures by frame signature")
    pd.add_argument("a")
    pd.add_argument("b")
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)

    if args.cmd == "listen":
        from .client import listen
        headers = {}
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        frames = listen(
            args.url, headers=headers, origin=args.origin,
            subprotocols=args.subprotocol or None,
            sends=args.send, duration=args.duration,
        )
        print(_render(frames))
        if args.save:
            with open(args.save, "w") as fh:
                fh.write(to_jsonl(frames))
            print(f"\nsaved {len(frames)} frames -> {args.save}", file=sys.stderr)
        return 0

    if args.cmd == "show":
        print(_render(from_jsonl(open(args.file).read())))
        return 0

    if args.cmd == "diff":
        d = diff(from_jsonl(open(args.a).read()), from_jsonl(open(args.b).read()))
        for sig in d["added"]:
            print(f"+ {sig[0]:5} {sig[1]:12} {sig[2]}")
        for sig in d["removed"]:
            print(f"- {sig[0]:5} {sig[1]:12} {sig[2]}")
        if not d["added"] and not d["removed"]:
            print("(identical signatures)")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
