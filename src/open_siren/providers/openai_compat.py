"""OpenAI-compatible Chat Completions provider (OpenAI, OpenRouter, vLLM, etc.)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

import httpx

from open_siren.providers.base import SleepFn, request_with_retry, resolve_api_key
from open_siren.types import (
    Message,
    ModelResponse,
    TokenUsage,
    ToolCall,
    ToolDefinition,
)


def _extract_text_content(raw_content: Any) -> str:
    if raw_content is None:
        return ""
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, list):
        parts: list[str] = []
        for item in raw_content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return str(raw_content)


def _extract_reasoning(raw_message: Mapping[str, Any]) -> str | None:
    raw = raw_message.get("reasoning_content")
    if raw is None or raw == "":
        raw = raw_message.get("reasoning")
    if raw is None or raw == "":
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        parts = [
            item["text"]
            for item in raw
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ]
        joined = "\n".join(parts)
        return joined or None
    return str(raw)


def _serialize_message(msg: Message) -> dict[str, Any]:
    if msg.role in ("system", "user"):
        return {"role": msg.role, "content": msg.content}

    if msg.role == "assistant":
        payload: dict[str, Any] = {"role": "assistant"}
        if msg.content or not msg.tool_calls:
            payload["content"] = msg.content
        else:
            payload["content"] = None
        if msg.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in msg.tool_calls
            ]
        return payload

    if msg.role == "tool":
        if msg.tool_result is None:
            raise ValueError("Message with role='tool' must include tool_result.")
        return {
            "role": "tool",
            "tool_call_id": msg.tool_result.tool_call_id,
            "content": msg.tool_result.content,
        }

    raise ValueError(f"Unsupported message role: {msg.role!r}")


def _parse_tool_calls(raw_tool_calls: Any) -> tuple[ToolCall, ...]:
    if not raw_tool_calls:
        return ()
    parsed: list[ToolCall] = []
    for raw_tc in raw_tool_calls:
        fn = raw_tc.get("function") or {}
        name = str(fn.get("name", ""))
        raw_args = fn.get("arguments", "{}")
        if isinstance(raw_args, dict):
            arguments: dict[str, Any] = raw_args
        elif isinstance(raw_args, str):
            stripped = raw_args.strip()
            if not stripped:
                arguments = {}
            else:
                try:
                    decoded = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON arguments for tool call {name!r}: {exc}"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise ValueError(
                        f"Tool call arguments for {name!r} must decode to a JSON object."
                    )
                arguments = decoded
        else:
            raise ValueError(f"Unsupported tool call arguments type for {name!r}: {type(raw_args)}")
        parsed.append(
            ToolCall(
                id=str(raw_tc["id"]),
                name=name,
                arguments=arguments,
            )
        )
    return tuple(parsed)


class OpenAICompatProvider:
    """ModelProvider backed by an OpenAI-compatible Chat Completions HTTP API."""

    name: str = "openai_compat"

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key_env: str = "OPENAI_API_KEY",
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        timeout_s: float = 120.0,
        max_retries: int = 4,
        client: httpx.AsyncClient | None = None,
        *,
        sleep: SleepFn = asyncio.sleep,
    ) -> None:
        self._api_key = resolve_api_key(api_key_env, api_key)
        self._base_url = base_url.rstrip("/")
        self._extra_headers = dict(extra_headers) if extra_headers else {}
        self._max_retries = max_retries
        self._sleep = sleep
        self._owns_client = client is None
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout_s)

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self._extra_headers)
        return headers

    def _build_payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition],
        *,
        model: str,
        temperature: float | None,
        max_tokens: int,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [_serialize_message(m) for m in messages],
            "max_tokens": max_tokens,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
                for tool in tools
            ]
        return payload

    def _parse_response(self, data: Mapping[str, Any]) -> ModelResponse:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("OpenAI-compatible API response contains no choices.")

        choice = choices[0]
        raw_msg = choice.get("message") or {}
        content = _extract_text_content(raw_msg.get("content"))
        tool_calls = _parse_tool_calls(raw_msg.get("tool_calls"))
        reasoning = _extract_reasoning(raw_msg)

        raw_usage = data.get("usage") or {}
        usage = TokenUsage(
            input_tokens=int(raw_usage.get("prompt_tokens") or 0),
            output_tokens=int(raw_usage.get("completion_tokens") or 0),
        )
        stop_reason = choice.get("finish_reason")

        return ModelResponse(
            message=Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls,
                reasoning=reasoning,
            ),
            stop_reason=str(stop_reason) if stop_reason is not None else None,
            usage=usage,
        )

    async def complete(
        self,
        messages: list[Message],
        tools: list[ToolDefinition],
        *,
        model: str,
        temperature: float | None = None,
        max_tokens: int = 4096,
        episode_hints: Mapping[str, str] | None = None,
    ) -> ModelResponse:
        # Real providers MUST ignore episode_hints and never transmit them.
        del episode_hints

        url = f"{self._base_url}/chat/completions"
        payload = self._build_payload(
            messages,
            tools,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        response = await request_with_retry(
            self._client,
            "POST",
            url,
            json=payload,
            headers=self._build_headers(),
            max_retries=self._max_retries,
            sleep=self._sleep,
        )
        return self._parse_response(response.json())

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
