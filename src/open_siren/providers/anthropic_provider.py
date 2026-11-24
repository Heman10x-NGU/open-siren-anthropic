"""Anthropic Messages API provider over httpx."""

from __future__ import annotations

import asyncio
import copy
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

ANTHROPIC_VERSION = "2023-06-01"


def _append_user_block(
    translated: list[dict[str, Any]],
    block: dict[str, Any],
) -> None:
    """Append a block to the trailing user message, coalescing consecutive user/tool turns."""
    if translated and translated[-1]["role"] == "user":
        prev_content = translated[-1]["content"]
        if isinstance(prev_content, str):
            translated[-1]["content"] = [{"type": "text", "text": prev_content}, block]
        else:
            prev_content.append(block)
    else:
        translated.append({"role": "user", "content": [block]})


def _translate_messages(messages: list[Message]) -> tuple[str | None, list[dict[str, Any]]]:
    """Split system prompts from conversation messages and translate to Anthropic blocks."""
    system_parts: list[str] = []
    translated: list[dict[str, Any]] = []

    for msg in messages:
        if msg.role == "system":
            if msg.content:
                system_parts.append(msg.content)
            continue

        if msg.role == "user":
            if translated and translated[-1]["role"] == "user":
                _append_user_block(translated, {"type": "text", "text": msg.content})
            else:
                translated.append({"role": "user", "content": msg.content})
            continue

        if msg.role == "tool":
            if msg.tool_result is None:
                raise ValueError("Message with role='tool' must include tool_result.")
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": msg.tool_result.tool_call_id,
                "content": msg.tool_result.content,
            }
            if msg.tool_result.is_error:
                block["is_error"] = True
            _append_user_block(translated, block)
            continue

        if msg.role == "assistant":
            raw_content = (
                msg.provider_raw.get("content") if isinstance(msg.provider_raw, dict) else None
            )
            if isinstance(raw_content, list):
                translated.append(
                    {
                        "role": "assistant",
                        "content": copy.deepcopy(raw_content),
                    }
                )
                continue

            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for tc in msg.tool_calls:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    }
                )
            if not blocks:
                blocks.append({"type": "text", "text": ""})
            translated.append({"role": "assistant", "content": blocks})
            continue

        raise ValueError(f"Unsupported message role: {msg.role!r}")

    system_text = "\n\n".join(system_parts) if system_parts else None
    return system_text, translated


class AnthropicProvider:
    """ModelProvider backed by the Anthropic Messages API over httpx."""

    name: str = "anthropic"

    def __init__(
        self,
        api_key_env: str = "ANTHROPIC_API_KEY",
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com",
        thinking_budget: int | None = None,
        timeout_s: float = 120.0,
        max_retries: int = 4,
        client: httpx.AsyncClient | None = None,
        *,
        sleep: SleepFn = asyncio.sleep,
    ) -> None:
        self._api_key = resolve_api_key(api_key_env, api_key)
        if thinking_budget is not None and thinking_budget <= 0:
            raise ValueError(f"thinking_budget must be a positive integer, got {thinking_budget}")
        self._base_url = base_url.rstrip("/")
        self._thinking_budget = thinking_budget
        self._max_retries = max_retries
        self._sleep = sleep
        self._owns_client = client is None
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout_s)

    def _messages_url(self) -> str:
        if self._base_url.endswith("/v1"):
            return f"{self._base_url}/messages"
        return f"{self._base_url}/v1/messages"

    def _build_headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def _build_payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition],
        *,
        model: str,
        temperature: float | None,
        max_tokens: int,
    ) -> dict[str, Any]:
        system_text, translated_messages = _translate_messages(messages)
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": translated_messages,
        }
        if system_text is not None:
            payload["system"] = system_text
        if temperature is not None:
            payload["temperature"] = temperature
        if self._thinking_budget is not None:
            payload["thinking"] = {
                "type": "enabled",
                "budget_tokens": self._thinking_budget,
            }
        if tools:
            payload["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }
                for tool in tools
            ]
        return payload

    def _parse_response(self, data: Mapping[str, Any]) -> ModelResponse:
        raw_blocks = data.get("content")
        if not isinstance(raw_blocks, list):
            raise ValueError("Anthropic Messages API response missing 'content' block list.")

        text_parts: list[str] = []
        thinking_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for block in raw_blocks:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "text":
                text_val = block.get("text")
                if isinstance(text_val, str):
                    text_parts.append(text_val)
            elif block_type == "thinking":
                thinking_val = block.get("thinking")
                if isinstance(thinking_val, str) and thinking_val:
                    thinking_parts.append(thinking_val)
            elif block_type == "tool_use":
                raw_input = block.get("input")
                arguments = raw_input if isinstance(raw_input, dict) else {}
                tool_calls.append(
                    ToolCall(
                        id=str(block["id"]),
                        name=str(block["name"]),
                        arguments=arguments,
                    )
                )

        content = "\n".join(text_parts)
        reasoning = "\n\n".join(thinking_parts) if thinking_parts else None
        provider_raw: dict[str, Any] = {"content": copy.deepcopy(raw_blocks)}

        raw_usage = data.get("usage") or {}
        usage = TokenUsage(
            input_tokens=int(raw_usage.get("input_tokens") or 0),
            output_tokens=int(raw_usage.get("output_tokens") or 0),
        )
        stop_reason = data.get("stop_reason")

        return ModelResponse(
            message=Message(
                role="assistant",
                content=content,
                tool_calls=tuple(tool_calls),
                reasoning=reasoning,
                provider_raw=provider_raw,
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
            self._messages_url(),
            json=payload,
            headers=self._build_headers(),
            max_retries=self._max_retries,
            sleep=self._sleep,
        )
        return self._parse_response(response.json())

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
