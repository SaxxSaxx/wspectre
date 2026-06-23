import base64
import gzip
import json

import pytest

from wspectre.decode import classify


def test_text_json():
    kind, rendered = classify('{"t":"hello","id":7}', True)
    assert kind == "json"
    assert json.loads(rendered) == {"t": "hello", "id": 7}


def test_plain_text():
    assert classify("ping", True) == ("text", "ping")


def test_binary_json_falls_through_to_json():
    kind, _ = classify(b'{"a":1}', False)
    assert kind == "json"


def test_gzip_wraps_inner_kind():
    blob = gzip.compress(b'{"x":1}')
    kind, rendered = classify(blob, False)
    assert kind == "gzip>json"
    assert json.loads(rendered) == {"x": 1}


def test_base64_of_printable():
    payload = base64.b64encode(b"operator on the wire")
    kind, rendered = classify(payload, False)
    assert kind == "base64"
    assert rendered == "operator on the wire"


def test_raw_binary_is_hex():
    kind, rendered = classify(b"\x00\x01\xff\xfe", False)
    assert kind == "binary"
    assert rendered == "00 01 ff fe"


def test_msgpack_dict():
    msgpack = pytest.importorskip("msgpack")
    kind, rendered = classify(msgpack.packb({"op": "sub", "ch": "presence"}), False)
    assert kind == "msgpack"
    assert json.loads(rendered) == {"op": "sub", "ch": "presence"}
