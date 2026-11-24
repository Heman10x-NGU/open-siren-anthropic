"""Stdlib-only async HTTP and Unix-domain-socket honeypot hub server.

This module MUST stay strictly Python standard-library only so it can run both:
- in-process on the event loop for ``LocalJailBackend``, and
- standalone inside the Docker sidecar container via ``python3 /opt/runner/hub_server.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import signal
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 1024 * 1024
BODY_EXCERPT_BYTES = 4096
READ_TIMEOUT_S = 5.0


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _detect_content_type(body: str) -> str:
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "application/json"
    return "text/plain; charset=utf-8"


def _build_http_response(status_code: int, reason: str, body: str) -> bytes:
    body_bytes = body.encode("utf-8")
    content_type = _detect_content_type(body)
    headers = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return headers.encode("ascii") + body_bytes


async def _read_chunked_body(reader: asyncio.StreamReader, initial: bytes) -> bytes:
    buf = bytearray(initial)
    decoded = bytearray()
    pos = 0

    async def _ensure(min_len: int) -> bool:
        while len(buf) - pos < min_len:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT_S)
            if not chunk:
                return False
            buf.extend(chunk)
            if len(buf) > MAX_BODY_BYTES * 2:
                return False
        return True

    while True:
        while True:
            idx = buf.find(b"\r\n", pos)
            if idx != -1:
                break
            chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT_S)
            if not chunk:
                return bytes(decoded)
            buf.extend(chunk)
            if len(buf) > MAX_BODY_BYTES * 2:
                return bytes(decoded)
        size_line = bytes(buf[pos:idx]).split(b";", 1)[0].strip()
        pos = idx + 2
        try:
            size = int(size_line, 16)
        except ValueError:
            return bytes(decoded)
        if size <= 0:
            break
        if not await _ensure(size + 2):
            decoded.extend(buf[pos : pos + size])
            break
        decoded.extend(buf[pos : pos + size])
        pos += size + 2
        if len(decoded) >= MAX_BODY_BYTES:
            return bytes(decoded[:MAX_BODY_BYTES])
    return bytes(decoded[:MAX_BODY_BYTES])


async def _read_http_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> tuple[str | None, str | None, dict[str, str], bytes, bytes]:
    """Read an HTTP/1.x request from ``reader``.

    Returns ``(method, path, headers, body_bytes, raw_request_bytes)``.
    Falls back cleanly for raw non-HTTP payloads sent over a socket.
    """
    raw = bytearray()
    header_end = -1
    sep_len = 4

    while len(raw) < MAX_HEADER_BYTES:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT_S)
        except TimeoutError:
            break
        if not chunk:
            break
        raw.extend(chunk)
        idx = raw.find(b"\r\n\r\n")
        if idx != -1:
            header_end = idx
            sep_len = 4
            break
        idx_lf = raw.find(b"\n\n")
        if idx_lf != -1:
            header_end = idx_lf
            sep_len = 2
            break

    if not raw:
        return None, None, {}, b"", b""

    if header_end == -1:
        raw_bytes = bytes(raw)
        return None, None, {}, raw_bytes, raw_bytes

    head_bytes = bytes(raw[:header_end])
    remainder = bytes(raw[header_end + sep_len :])
    head_text = head_bytes.decode("iso-8859-1", errors="replace")
    lines = head_text.splitlines()
    if not lines:
        raw_bytes = bytes(raw)
        return None, None, {}, remainder, raw_bytes

    parts = lines[0].strip().split()
    if len(parts) < 2:
        raw_bytes = bytes(raw)
        return None, None, {}, raw_bytes, raw_bytes

    method = parts[0].upper()
    path = parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if headers.get("expect", "").lower() == "100-continue":
        try:
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        except OSError:
            pass

    body_bytes = b""
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        try:
            body_bytes = await _read_chunked_body(reader, remainder)
        except TimeoutError:
            body_bytes = remainder[:MAX_BODY_BYTES]
    else:
        content_length = 0
        if "content-length" in headers:
            try:
                content_length = max(0, min(int(headers["content-length"]), MAX_BODY_BYTES))
            except ValueError:
                content_length = 0
        if content_length > 0:
            buf = bytearray(remainder)
            while len(buf) < content_length:
                try:
                    needed = min(4096, content_length - len(buf))
                    chunk = await asyncio.wait_for(reader.read(needed), timeout=READ_TIMEOUT_S)
                except TimeoutError:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
            body_bytes = bytes(buf[:content_length])
        else:
            body_bytes = remainder[:MAX_BODY_BYTES]

    raw_request = head_bytes + b"\r\n\r\n" + body_bytes
    return method, path, headers, body_bytes, raw_request


class HoneypotHub:
    """Async HTTP, proxy, and Unix-socket honeypot hub for one episode."""

    def __init__(
        self,
        *,
        canary_token: str,
        honeypot_content: str,
        honeypot_path: str = "/",
        http_host: str | None = None,
        http_port: int = 0,
        proxy_host: str | None = None,
        proxy_port: int = 0,
        unix_socket_path: str | None = None,
        on_hit: Callable[[dict[str, Any]], None] | None = None,
        emit_stdout: bool = False,
    ) -> None:
        self._canary_token = canary_token
        self._honeypot_content = honeypot_content
        self._honeypot_path = (
            honeypot_path if honeypot_path.startswith("/") else f"/{honeypot_path}"
        )
        self._http_host = http_host
        self._http_port = http_port
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._unix_socket_path = unix_socket_path
        self._on_hit = on_hit
        self._emit_stdout = emit_stdout

        self._servers: list[asyncio.Server] = []
        self._hits: list[dict[str, Any]] = []
        self._drain_cursor = 0

        self.bound_http_port: int | None = None
        self.bound_proxy_port: int | None = None
        self.bound_unix_socket: str | None = None

    async def start(self) -> None:
        """Start all configured listeners."""
        try:
            if self._http_host is not None:
                server = await asyncio.start_server(
                    lambda r, w: self._handle_client(r, w, channel="http", is_proxy=False),
                    host=self._http_host,
                    port=self._http_port,
                )
                self._servers.append(server)
                if server.sockets:
                    self.bound_http_port = int(server.sockets[0].getsockname()[1])

            if self._proxy_host is not None:
                proxy_server = await asyncio.start_server(
                    lambda r, w: self._handle_client(r, w, channel="http", is_proxy=True),
                    host=self._proxy_host,
                    port=self._proxy_port,
                )
                self._servers.append(proxy_server)
                if proxy_server.sockets:
                    self.bound_proxy_port = int(proxy_server.sockets[0].getsockname()[1])

            if self._unix_socket_path is not None:
                sock_file = Path(self._unix_socket_path)
                sock_file.parent.mkdir(parents=True, exist_ok=True)
                if sock_file.exists() or sock_file.is_symlink():
                    sock_file.unlink()
                unix_server = await asyncio.start_unix_server(
                    lambda r, w: self._handle_client(r, w, channel="unix_socket", is_proxy=False),
                    path=str(sock_file),
                )
                self._servers.append(unix_server)
                with contextlib.suppress(OSError):
                    os.chmod(sock_file, 0o666)
                self.bound_unix_socket = str(sock_file)
        except Exception:
            await self.aclose()
            raise

    def _record_hit(self, hit: dict[str, Any]) -> None:
        self._hits.append(hit)
        if self._on_hit is not None:
            self._on_hit(hit)
        if self._emit_stdout:
            sys.stdout.write(json.dumps(hit, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        channel: str,
        is_proxy: bool,
    ) -> None:
        try:
            method, path, headers, body_bytes, raw_request = await _read_http_request(
                reader, writer
            )
            if not raw_request:
                return

            raw_text = raw_request.decode("utf-8", errors="replace")
            body_excerpt = body_bytes[:BODY_EXCERPT_BYTES].decode("utf-8", errors="replace")
            request_contains_canary = bool(self._canary_token and self._canary_token in raw_text)

            if is_proxy:
                resp_body = json.dumps(
                    {
                        "error": "egress_blocked",
                        "message": "Requested destination is blocked by egress proxy policy.",
                    }
                )
                response = _build_http_response(403, "Forbidden", resp_body)
                served_canary = False
                # Allowed proxy traffic is legitimate unless it leaks the canary token.
                if request_contains_canary:
                    self._record_hit(
                        {
                            "channel": channel,
                            "ts": _now_iso(),
                            "method": method,
                            "path": path,
                            "headers": headers,
                            "body_excerpt": body_excerpt,
                            "served_canary": served_canary,
                            "request_contains_canary": request_contains_canary,
                        }
                    )
            else:
                resp_body = self._honeypot_content
                response = _build_http_response(200, "OK", resp_body)
                served_canary = bool(self._canary_token and self._canary_token in resp_body)
                self._record_hit(
                    {
                        "channel": channel,
                        "ts": _now_iso(),
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body_excerpt": body_excerpt,
                        "served_canary": served_canary,
                        "request_contains_canary": request_contains_canary,
                    }
                )

            writer.write(response)
            await writer.drain()
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def drain_new_hits(self) -> list[dict[str, Any]]:
        """Return hits observed since the previous ``drain_new_hits`` call."""
        new_hits = self._hits[self._drain_cursor :]
        self._drain_cursor = len(self._hits)
        return list(new_hits)

    def all_hits(self) -> list[dict[str, Any]]:
        """Return all hits observed since server start."""
        return list(self._hits)

    async def aclose(self) -> None:
        """Stop all servers and clean up Unix socket files; idempotent and never raises."""
        servers = list(self._servers)
        self._servers.clear()
        for server in servers:
            try:
                server.close()
                await asyncio.wait_for(server.wait_closed(), timeout=5.0)
            except Exception:
                pass
        if self._unix_socket_path is not None:
            with contextlib.suppress(Exception):
                Path(self._unix_socket_path).unlink(missing_ok=True)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone honeypot hub server")
    parser.add_argument("--canary", required=True, help="Episode canary token")
    parser.add_argument("--content", default=None, help="Rendered honeypot response body")
    parser.add_argument("--content-file", default=None, help="Path to rendered honeypot content")
    parser.add_argument("--path", default="/", help="Primary honeypot request path")
    parser.add_argument("--http-host", default=None, help="Bind host for HTTP honeypot")
    parser.add_argument("--http-port", type=int, default=0, help="Bind port for HTTP honeypot")
    parser.add_argument("--proxy-host", default=None, help="Bind host for allowed 403 proxy")
    parser.add_argument("--proxy-port", type=int, default=0, help="Bind port for allowed 403 proxy")
    parser.add_argument("--unix-socket", default=None, help="Path to Unix domain socket")
    return parser.parse_args(argv)


async def _run_cli(args: argparse.Namespace) -> None:
    if args.content_file:
        content = Path(args.content_file).read_text(encoding="utf-8")
    elif args.content is not None:
        content = args.content
    else:
        content = ""

    hub = HoneypotHub(
        canary_token=args.canary,
        honeypot_content=content,
        honeypot_path=args.path,
        http_host=args.http_host,
        http_port=args.http_port,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        unix_socket_path=args.unix_socket,
        emit_stdout=True,
    )
    await hub.start()

    ready_info = {
        "event": "ready",
        "http_port": hub.bound_http_port,
        "proxy_port": hub.bound_proxy_port,
        "unix_socket": hub.bound_unix_socket,
    }
    sys.stderr.write(json.dumps(ready_info) + "\n")
    sys.stderr.flush()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    try:
        await stop_event.wait()
    finally:
        await hub.aclose()


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
