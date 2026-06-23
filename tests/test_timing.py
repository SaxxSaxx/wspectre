from wspectre.timing import detect_heartbeat, intervals


def test_intervals():
    assert intervals([0, 1, 3, 6]) == [1, 2, 3]


def test_detects_steady_heartbeat():
    ts = [0, 5, 10, 15, 20, 20.3]  # 5s keepalive, one stray frame
    hb = detect_heartbeat(ts)
    assert hb is not None
    assert abs(hb["period"] - 5.0) < 0.1
    assert hb["count"] == 4


def test_no_heartbeat_when_irregular():
    assert detect_heartbeat([0, 1, 3, 7, 15]) is None


def test_too_few_samples():
    assert detect_heartbeat([0, 5]) is None
