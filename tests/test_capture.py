from wspectre.capture import Frame, diff, from_jsonl, to_jsonl


def _f(ts, direction, op, data, is_text):
    return Frame(ts, direction, op, data, is_text)


def test_jsonl_roundtrip():
    frames = [
        _f(0.0, "up", "text", b'{"op":"sub"}', True),
        _f(0.5, "down", "binary", b"\x00\x01\x02", False),
    ]
    restored = from_jsonl(to_jsonl(frames))
    assert restored == frames


def test_signature_buckets_by_size_and_kind():
    f = _f(0.0, "down", "text", b'{"a":1}', True)
    assert f.signature() == ("down", "json", "<=16")


def test_diff_reports_added_and_removed():
    a = [_f(0, "down", "text", b"hi", True)]
    b = [
        _f(0, "down", "text", b"hi", True),
        _f(1, "down", "text", b'{"presence":true}', True),
    ]
    d = diff(a, b)
    assert ("down", "json", "<=64") in d["added"]
    assert d["removed"] == []


def test_diff_identical():
    a = [_f(0, "up", "text", b"x", True)]
    assert diff(a, list(a)) == {"added": [], "removed": []}
