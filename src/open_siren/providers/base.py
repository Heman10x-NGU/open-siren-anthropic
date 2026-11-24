"""Shared HTTP retry and API key helpers for model providers."""

from __future__ import annotations

import asyncio
import math
import os
import random
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429})

SleepFn = Callable[[float], Awaitable[None]]
JitterFn = Callable[[float], float]


def resolve_api_key(api_key_env: str, api_key: str | None = None) -> str:
    """Resolve an API key from an explicit value or environment variable.

    Fails fast with a ValueError naming ``api_key_env`` when missing or empty.
    """
    if api_key is not None:
        cleaned = api_key.strip()
        if not cleaned:
            raise ValueError(
                f"API key is empty (explicit value provided for env var {api_key_env!r})."
            )
        return cleaned

    if not api_key_env or not api_key_env.strip():
        raise ValueError("api_key_env must be a non-empty environment variable name.")

    env_val = os.environ.get(api_key_env, "").strip()
    if not env_val:
        raise ValueError(
            f"Missing API key: environment variable {api_key_env!r} is not set or empty."
        )
    return env_val


def parse_retry_after(header_value: str | None) -> float | None:
    """Parse an HTTP Retry-After header (numeric seconds or HTTP-date) into delay seconds."""
    if not header_value:
        return None
    raw = header_value.strip()
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return max(0.0, (dt - datetime.now(UTC)).total_seconds())

    if math.isnan(seconds) or math.isinf(seconds):
        return None
    return max(0.0, seconds)


def _is_retryable_status(status_code: int) -> bool:
    return status_code in RETRYABLE_STATUS_CODES or 500 <= status_code < 600


def _compute_backoff(
    attempt: int,
    *,
    base_delay_s: float,
    max_delay_s: float,
    jitter: JitterFn | None,
) -> float:
    raw_delay = min(max_delay_s, base_delay_s * (2**attempt))
    if jitter is not None:
        return max(0.0, jitter(raw_delay))
    return raw_delay * (0.5 + random.random() * 0.5)


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    json: Any = None,
    headers: Mapping[str, str] | None = None,
    max_retries: int = 4,
    base_delay_s: float = 0.5,
    max_delay_s: float = 30.0,
    sleep: SleepFn = asyncio.sleep,
    jitter: JitterFn | None = None,
) -> httpx.Response:
    """Send an HTTP request with exponential backoff + jitter on 429, 5xx, and transport errors.

    Honors numeric (and HTTP-date) ``Retry-After`` response headers when present.
    Non-retryable 4xx responses raise ``httpx.HTTPStatusError`` immediately.
    """
    if max_retries < 0:
        raise ValueError(f"max_retries must be >= 0, got {max_retries}")

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, url, json=json, headers=headers)
        except httpx.TransportError:
            if attempt >= max_retries:
                raise
            delay = _compute_backoff(
                attempt,
                base_delay_s=base_delay_s,
                max_delay_s=max_delay_s,
                jitter=jitter,
            )
            await sleep(delay)
            continue

        if not _is_retryable_status(response.status_code):
            response.raise_for_status()
            return response

        if attempt >= max_retries:
            response.raise_for_status()

        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        if retry_after is not None:
            delay = retry_after
        else:
            delay = _compute_backoff(
                attempt,
                base_delay_s=base_delay_s,
                max_delay_s=max_delay_s,
                jitter=jitter,
            )
        await sleep(delay)

    raise RuntimeError("request_with_retry exited unexpectedly")  # pragma: no cover
