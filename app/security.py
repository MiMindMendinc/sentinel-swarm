from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_list(name: str, default: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(name, default).split(",") if item.strip())


MAX_HTTP_BODY_BYTES = _env_int("SENTINEL_MAX_HTTP_BODY_BYTES", 4096, 512, 1_048_576)
MAX_WS_MESSAGE_BYTES = _env_int("SENTINEL_MAX_WS_MESSAGE_BYTES", 4096, 512, 1_048_576)
RATE_LIMIT_REQUESTS = _env_int("SENTINEL_RATE_LIMIT_REQUESTS", 60, 1, 10_000)
RATE_LIMIT_WINDOW_SECONDS = _env_int("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600)
ALLOWED_HOSTS = _env_list(
    "SENTINEL_ALLOWED_HOSTS",
    "localhost,127.0.0.1,[::1],testserver",
)
ALLOWED_ORIGINS = _env_list(
    "SENTINEL_ALLOWED_ORIGINS",
    "http://localhost:7777,http://127.0.0.1:7777,http://testserver,https://testserver",
)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'none'; "
        "connect-src 'self' ws://localhost:* ws://127.0.0.1:* "
        "wss://localhost:* wss://127.0.0.1:*; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def strict_json_loads(value: str | bytes) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


class FixedWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


mission_rate_limiter = FixedWindowRateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


def client_key(scope: Scope) -> str:
    client = scope.get("client")
    host = client[0] if client else "unknown"
    return f"mission:{host}"


def websocket_origin_allowed(scope: Scope) -> bool:
    headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope["headers"]}
    origin = headers.get("origin")
    if origin is None:
        return True
    if origin in ALLOWED_ORIGINS:
        return True
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    host = headers.get("host", "").lower()
    return parsed.scheme in {"http", "https"} and parsed.netloc.lower() == host


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                if scope.get("path", "").startswith("/api/") or scope.get("path") == "/openapi.json":
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BoundedMissionBodyMiddleware:
    def __init__(self, app: ASGIApp, maximum_bytes: int = MAX_HTTP_BODY_BYTES) -> None:
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/api/missions"
        ):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope["headers"]}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
                await response(scope, receive, send)
                return
            if declared_length > self.maximum_bytes:
                response = JSONResponse({"detail": "Mission request body is too large"}, status_code=413)
                await response(scope, receive, send)
                return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                response = JSONResponse({"detail": "Client disconnected"}, status_code=400)
                await response(scope, receive, send)
                return
            body = message.get("body", b"")
            total += len(body)
            if total > self.maximum_bytes:
                response = JSONResponse({"detail": "Mission request body is too large"}, status_code=413)
                await response(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        buffered_body = b"".join(chunks)
        try:
            strict_json_loads(buffered_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        except ValueError:
            response = JSONResponse(
                {"detail": "Mission request body must use strict JSON without duplicate keys"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": buffered_body, "more_body": False}

        await self.app(scope, replay_receive, send)
