"""OpenAI-compatible moderation endpoint backed by ATR rules.

Gateways and frameworks that call an OpenAI-style ``/v1/moderations`` endpoint
(``POST {"input": ...}`` returning ``{"results": [{"flagged": ..., ...}]}``)
can use ATR as that backend without embedding a Python engine.

    from pyatr.moderation import moderation_result
    moderation_result("some prompt")

    # or run the reference server (standard library only):
    #   python -m pyatr.moderation --port 8000

Every rule is evaluated, but ``flagged`` is true only for a match whose
severity is at or above ``block_severity`` and whose rule is in ``lane``.
The defaults (``lane="enforce"``, ``block_severity="high"``) flag only stable
rules, because rules of lower maturity produce false positives on benign
text. ``categories`` and ``category_scores`` are keyed by the ATR rule ids
that flagged, not by OpenAI's fixed category names, and the scores are the
rules' confidence levels mapped to 1.0 / 0.7 / 0.4, not probabilities. The
extra ``atr_matches`` list carries every match with its maturity, for logging.

``flagged`` is a signal, not a block. With the defaults it is raised on the
enforce lane at high or critical severity -- the same matches
``pyatr.enforcement.is_blocking_eligible`` admits -- and this module blocks
nothing itself: whether a flagged input is refused is the consumer's decision.
A gateway that does refuse on ``flagged`` should keep the defaults; widening
``lane`` or lowering ``block_severity`` flags matches that no other ATR surface
would block on.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pyatr.engine import LANES, ATREngine, lane_allows
from pyatr.types import SEVERITY_ORDER, AgentEvent, ATRMatch

MODEL_NAME = "agent-threat-rules"
MODERATIONS_PATH = "/v1/moderations"
MAX_BODY_BYTES = 1_000_000
REQUEST_TIMEOUT_SECONDS = 30

_CONFIDENCE_SCORES = {"high": 1.0, "medium": 0.7, "low": 0.4}


def _input_texts(payload: Any) -> list[str]:
    """Turn OpenAI's ``input`` into the texts to moderate, one per result.

    A string gives one result, and a list of strings gives one result per
    string. A list of content parts (``{"type": "text", "text": ...}``, as in
    multimodal moderation) gives one result for their joined text; non-text
    parts such as images are not scanned. Anything else is rejected, so an
    input the endpoint cannot read is never reported as clean.
    """
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, list) and payload:
        if all(isinstance(item, str) for item in payload):
            return list(payload)
        if all(isinstance(item, dict) for item in payload):
            texts = [item.get("text") for item in payload if item.get("type", "text") == "text"]
            if texts and all(isinstance(text, str) for text in texts):
                return ["\n".join(texts)]
    raise ValueError("input must be a string, a non-empty list of strings, or a list of content parts")


def _validate(lane: str, block_severity: str) -> None:
    if lane not in LANES:
        raise ValueError(f"lane must be one of {LANES}, got {lane!r}")
    if block_severity not in SEVERITY_ORDER:
        raise ValueError(f"block_severity must be one of {sorted(SEVERITY_ORDER)}, got {block_severity!r}")


def _flags(match: ATRMatch, lane: str, block_severity: str) -> bool:
    severe = SEVERITY_ORDER.get(match.severity, 99) <= SEVERITY_ORDER[block_severity]
    return severe and lane_allows(match, lane)


def _result(engine: ATREngine, text: str, lane: str, block_severity: str) -> dict:
    matches = engine.evaluate(AgentEvent(content=text, event_type="llm_input", fields={"user_input": text})) if text.strip() else []
    flagging = [m for m in matches if _flags(m, lane, block_severity)]
    return {
        "flagged": bool(flagging),
        "categories": {m.rule_id: True for m in flagging},
        "category_scores": {m.rule_id: _CONFIDENCE_SCORES.get(m.confidence, 1.0) for m in flagging},
        "atr_matches": [
            {
                "rule_id": m.rule_id,
                "title": m.title,
                "severity": m.severity,
                "maturity": m.maturity,
                "flagged": m in flagging,
            }
            for m in matches
        ],
    }


def load_engine(rules_dir: str | Path | None = None) -> ATREngine:
    """Load an engine with every rule (hunt lane); flagging applies the lane per match."""
    engine = ATREngine()
    loaded = engine.load_rules_from_directory(Path(rules_dir)) if rules_dir is not None else engine.load_default_rules()
    if not loaded:
        raise RuntimeError("pyatr.moderation loaded 0 rules; check the pyatr install or rules_dir")
    return engine


def moderation_result(
    payload: Any,
    *,
    engine: ATREngine | None = None,
    lane: str = "enforce",
    block_severity: str = "high",
) -> dict:
    """Evaluate ``payload`` (an OpenAI ``input``) and return a moderation response.

    One result is returned per input string. Pass a loaded ``engine`` to avoid
    loading the rules on every call.
    """
    _validate(lane, block_severity)
    engine = engine or load_engine()
    return {
        "id": "modr-atr",
        "model": MODEL_NAME,
        "results": [_result(engine, text, lane, block_severity) for text in _input_texts(payload)],
    }


def make_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    engine: ATREngine | None = None,
    lane: str = "enforce",
    block_severity: str = "high",
) -> ThreadingHTTPServer:
    """Build the reference server for ``POST /v1/moderations`` (call ``serve_forever()``)."""
    _validate(lane, block_severity)
    engine = engine or load_engine()

    class Handler(BaseHTTPRequestHandler):
        timeout = REQUEST_TIMEOUT_SECONDS  # slow or stalled clients do not hold a thread forever

        def _send(self, status: int, body: dict) -> None:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _error(self, status: int, message: str) -> None:
            self._send(status, {"error": {"message": message, "type": "invalid_request_error"}})

        def _read_body(self) -> bytes | None:
            """Read a body that declares its length; send an error and return None otherwise."""
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower() or "Content-Length" not in self.headers:
                self._error(411, "Content-Length is required")
                return None
            try:
                length = int(self.headers["Content-Length"])
            except ValueError:
                length = -1
            if length < 0:
                self._error(400, "invalid Content-Length")
                return None
            if length > MAX_BODY_BYTES:
                self._error(413, f"request body over {MAX_BODY_BYTES} bytes")
                return None
            body = self.rfile.read(length)
            if len(body) != length:
                self._error(400, "request body shorter than Content-Length")
                return None
            return body

        def do_POST(self) -> None:  # noqa: N802 - stdlib API name
            if urlsplit(self.path).path.rstrip("/") != MODERATIONS_PATH:
                self._error(404, f"not found; POST {MODERATIONS_PATH}")
                return
            raw = self._read_body()
            if raw is None:
                return
            try:
                body = json.loads(raw)
                if not isinstance(body, dict) or "input" not in body:
                    raise ValueError('request body must be a JSON object with an "input" field')
                result = moderation_result(body["input"], engine=engine, lane=lane, block_severity=block_severity)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                self._error(400, "request body is not valid JSON")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except Exception:  # never drop the connection without an answer
                self._send(500, {"error": {"message": "internal error", "type": "server_error"}})
                return
            self._send(200, result)

        def _method_not_allowed(self) -> None:
            self._error(405, f"method not allowed; POST {MODERATIONS_PATH}")

        do_GET = do_PUT = do_PATCH = do_DELETE = _method_not_allowed  # noqa: N815

        def log_message(self, *_args: Any) -> None:
            pass  # quiet by default; put a real server in front for access logs

    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI wrapper
    parser = argparse.ArgumentParser(prog="python -m pyatr.moderation", description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--lane", default="enforce", choices=LANES)
    parser.add_argument("--block-severity", default="high", choices=sorted(SEVERITY_ORDER))
    parser.add_argument("--rules-dir", default=None)
    args = parser.parse_args(argv)
    server = make_server(
        args.host, args.port, engine=load_engine(args.rules_dir), lane=args.lane, block_severity=args.block_severity
    )
    print(f"ATR moderation endpoint on http://{args.host}:{args.port}{MODERATIONS_PATH} (lane={args.lane})", flush=True)
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
