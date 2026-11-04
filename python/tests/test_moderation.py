"""Tests for the OpenAI-compatible moderation endpoint."""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from pyatr.moderation import load_engine, make_server, moderation_result

MARKER = "moderation-marker"

# id suffix -> (maturity, severity)
FIXTURES = {
    "00001": ("stable", "critical"),
    "00002": ("experimental", "critical"),
    "00003": ("stable", "medium"),
    "00004": ("test", "high"),
}


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    directory = tmp_path_factory.mktemp("moderation-rules")
    for suffix, (maturity, severity) in FIXTURES.items():
        rule = {
            "id": f"ATR-2099-{suffix}",
            "title": f"moderation fixture {suffix}",
            "severity": severity,
            "status": "experimental",
            "maturity": maturity,
            "detection": {
                "condition": "any",
                "conditions": [{"field": "user_input", "operator": "contains", "value": f"{MARKER}-{suffix}"}],
            },
        }
        (directory / f"ATR-2099-{suffix}.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    return load_engine(directory)


def _text(*suffixes: str) -> str:
    return " ".join(f"{MARKER}-{s}" for s in suffixes)


def test_response_has_the_openai_shape(engine) -> None:
    out = moderation_result(_text("00001"), engine=engine)
    assert out["model"] == "agent-threat-rules"
    (result,) = out["results"]
    assert result["flagged"] is True
    assert result["categories"] == {"ATR-2099-00001": True}
    assert set(result["category_scores"]) == {"ATR-2099-00001"}


def test_default_flags_only_stable_rules_at_high_or_above(engine) -> None:
    (result,) = moderation_result(_text("00001", "00002", "00003", "00004"), engine=engine)["results"]
    assert result["categories"] == {"ATR-2099-00001": True}
    recorded = {m["rule_id"]: (m["maturity"], m["flagged"]) for m in result["atr_matches"]}
    assert recorded == {
        "ATR-2099-00001": ("stable", True),
        "ATR-2099-00002": ("experimental", False),
        "ATR-2099-00003": ("stable", False),
        "ATR-2099-00004": ("test", False),
    }


def test_non_stable_match_alone_is_not_flagged(engine) -> None:
    (result,) = moderation_result(_text("00002"), engine=engine)["results"]
    assert result["flagged"] is False and result["categories"] == {}
    assert [m["rule_id"] for m in result["atr_matches"]] == ["ATR-2099-00002"]


@pytest.mark.parametrize(
    ("lane", "severity", "flagged"),
    [
        ("alert", "high", {"ATR-2099-00001", "ATR-2099-00004"}),
        ("hunt", "high", {"ATR-2099-00001", "ATR-2099-00002", "ATR-2099-00004"}),
        ("enforce", "medium", {"ATR-2099-00001", "ATR-2099-00003"}),
    ],
)
def test_lane_and_severity_options(engine, lane: str, severity: str, flagged: set) -> None:
    out = moderation_result(_text(*FIXTURES), engine=engine, lane=lane, block_severity=severity)
    assert set(out["results"][0]["categories"]) == flagged


def test_list_of_strings_gives_one_result_per_item(engine) -> None:
    out = moderation_result(["hello", _text("00001"), "bye"], engine=engine)
    assert [r["flagged"] for r in out["results"]] == [False, True, False]


def test_content_parts_give_one_result_and_skip_images(engine) -> None:
    parts = [
        {"type": "text", "text": "look at"},
        {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
        {"type": "text", "text": _text("00001")},
    ]
    (result,) = moderation_result(parts, engine=engine)["results"]
    assert result["flagged"] is True


@pytest.mark.parametrize(
    "payload",
    [
        None,
        5,
        {"text": "x"},
        [],
        [1, 2],
        ["a", 5, "b"],
        ["a", {"type": "text", "text": "b"}],
        [{"type": "text"}],
        [{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}],
    ],
)
def test_unreadable_input_is_rejected_not_reported_clean(engine, payload) -> None:
    with pytest.raises(ValueError, match="input must be"):
        moderation_result(payload, engine=engine)


@pytest.mark.parametrize("payload", ["", "   "])
def test_empty_input_is_not_flagged(engine, payload) -> None:
    (result,) = moderation_result(payload, engine=engine)["results"]
    assert result == {"flagged": False, "categories": {}, "category_scores": {}, "atr_matches": []}


@pytest.mark.parametrize("kwargs", [{"lane": "block"}, {"block_severity": "info"}])
def test_invalid_options_are_rejected(engine, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        moderation_result("x", engine=engine, **kwargs)


def test_empty_rules_dir_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="0 rules"):
        load_engine(tmp_path)


@pytest.fixture()
def server(engine):
    srv = make_server("127.0.0.1", 0, engine=engine)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _post(url: str, body: bytes, headers: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json", **(headers or {})}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def _raw(server: str, request: bytes) -> tuple[int, dict]:
    """Send a hand-written HTTP request, for headers urllib will not produce."""
    host, port = server.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=10) as conn:
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        data = b""
        while chunk := conn.recv(65536):
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(body)


def test_server_round_trip(server: str) -> None:
    status, body = _post(f"{server}/v1/moderations?trace=1", json.dumps({"input": _text("00001")}).encode())
    assert status == 200 and body["results"][0]["flagged"] is True


@pytest.mark.parametrize(
    ("path", "body", "status"),
    [
        ("/v1/other", b"{}", 404),
        ("/v1/moderations", b"not json", 400),
        ("/v1/moderations", b"[1, 2]", 400),
        ("/v1/moderations", b"{}", 400),
        ("/v1/moderations", b'{"input": 5}', 400),
        ("/v1/moderations", b'{"input": [1, 2]}', 400),
        ("/v1/moderations", b"[" * 200_000, 400),
    ],
)
def test_server_rejects_bad_requests(server: str, path: str, body: bytes, status: int) -> None:
    got, payload = _post(f"{server}{path}", body)
    assert got == status and "message" in payload["error"]


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        (b"Transfer-Encoding: chunked\r\n", 411),
        (b"", 411),
        (b"Content-Length: -1\r\n", 400),
        (b"Content-Length: abc\r\n", 400),
        (b"Content-Length: 2000000\r\n", 413),
        (b"Content-Length: 500\r\n", 400),
    ],
)
def test_server_requires_a_valid_content_length(server: str, headers: bytes, status: int) -> None:
    request = b"POST /v1/moderations HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n" + b'{"input": "hi"}'
    got, payload = _raw(server, request)
    assert got == status and "message" in payload["error"]


def test_server_answers_other_methods_with_json(server: str) -> None:
    got, payload = _raw(server, b"GET /v1/moderations HTTP/1.1\r\nHost: x\r\n\r\n")
    assert got == 405 and "message" in payload["error"]


def test_bundled_rules_flag_nothing_on_benign_text() -> None:
    (result,) = moderation_result("What is the weather in Paris tomorrow?")["results"]
    assert result["flagged"] is False
