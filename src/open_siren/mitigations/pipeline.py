"""Composable MitigationPipeline enforcing canonical ordering and fail-closed gating."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from open_siren.interfaces import EpisodeContext, Mitigation
from open_siren.mitigations.presets import CANONICAL_ORDER, canonicalize_mitigations
from open_siren.registry import MITIGATION_REGISTRY
from open_siren.types import GateDecision, ToolCall, ToolDefinition, ToolResult

_CANONICAL_INDEX: dict[str, int] = {name: idx for idx, name in enumerate(CANONICAL_ORDER)}


class MitigationPipeline:
    """Runs a set of mitigations in canonical order across prompt, tools, and pre-exec hooks."""

    def __init__(self, mitigations: Sequence[Mitigation] = ()) -> None:
        indexed = list(enumerate(mitigations))
        indexed.sort(
            key=lambda pair: (_CANONICAL_INDEX.get(pair[1].name, len(CANONICAL_ORDER)), pair[0])
        )
        self._mitigations: tuple[Mitigation, ...] = tuple(m for _, m in indexed)

    @property
    def mitigations(self) -> tuple[Mitigation, ...]:
        return self._mitigations

    @classmethod
    def from_names(
        cls,
        names: Iterable[str],
        configs: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> MitigationPipeline:
        """Instantiate canonicalized mitigations from MITIGATION_REGISTRY."""
        canonical = canonicalize_mitigations(names)
        cfg_map = configs or {}
        instances = [
            MITIGATION_REGISTRY.create(name, **dict(cfg_map.get(name, {}))) for name in canonical
        ]
        return cls(instances)

    def transform_system_prompt(self, prompt: str, ctx: EpisodeContext) -> str:
        current = prompt
        for mitigation in self._mitigations:
            current = mitigation.transform_system_prompt(current, ctx)
        return current

    def extra_tools(self, ctx: EpisodeContext) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        seen: set[str] = set()
        for mitigation in self._mitigations:
            for tool in mitigation.extra_tools(ctx):
                if tool.name in seen:
                    raise ValueError(f"Duplicate mitigation tool name: {tool.name!r}")
                seen.add(tool.name)
                tools.append(tool)
        return tools

    async def handle_tool_call(self, call: ToolCall, ctx: EpisodeContext) -> ToolResult | None:
        for mitigation in self._mitigations:
            result = await mitigation.handle_tool_call(call, ctx)
            if result is not None:
                return result
        return None

    async def pre_exec(self, command: str, ctx: EpisodeContext) -> GateDecision:
        last_decision = GateDecision(
            allow=True,
            mitigation="pipeline",
            stage="none",
            reason="no gate",
        )
        for mitigation in self._mitigations:
            try:
                decision = await mitigation.pre_exec(command, ctx)
            except Exception as exc:
                return GateDecision(
                    allow=False,
                    mitigation=mitigation.name,
                    stage="error",
                    risk_category="gate_error",
                    reason=f"gate_error_fail_closed: {exc}",
                )
            if not decision.allow:
                return decision
            if decision.stage != "none":
                last_decision = decision
        return last_decision
