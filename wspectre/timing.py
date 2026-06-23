"""Cadence analysis.

Real-time apps betray themselves through rhythm: keepalives, presence
pings, polling loops. detect_heartbeat() finds the dominant period in a
sequence of frame timestamps so the protocol's heartbeat falls out on its own.
"""


def intervals(timestamps):
    return [round(b - a, 6) for a, b in zip(timestamps, timestamps[1:])]


def detect_heartbeat(timestamps, tol=0.15, min_count=3):
    """Find the dominant periodic interval.

    Returns {"period", "count", "confidence"} or None when nothing is regular.
    `tol` is the fractional window an interval may drift and still count.
    """
    ivs = intervals(timestamps)
    if len(ivs) < min_count:
        return None

    best = None  # (avg_period, member_count)
    for cand in ivs:
        if cand <= 0:
            continue
        members = [x for x in ivs if abs(x - cand) <= tol * cand]
        if best is None or len(members) > best[1]:
            best = (sum(members) / len(members), len(members))

    if best is None or best[1] < min_count:
        return None
    period, count = best
    return {"period": round(period, 3), "count": count, "confidence": round(count / len(ivs), 3)}
