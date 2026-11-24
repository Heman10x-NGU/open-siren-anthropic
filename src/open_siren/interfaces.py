"""Wave 0 frozen Protocols, EpisodeContext, MitigationBase, and SHELL_TOOL."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from open_siren.types import (
    ExecResult,
    GateDecision,
    GradeResult,
    Message,
    ModelResponse,
    SandboxHandle,
    SandboxReport,
    ScenarioSpec,
    TelemetrySnapshot,
    ToolCall,
    ToolDefinition,
    ToolResult,
    TraceEvent,
)


@runtime_checkable
class ReportStore(Protocol):
    """Per-episode store for agent-submitted and pre-seeded sandbox weakness reports."""

    def submit(self, report: SandboxReport) -> None: ...
    def list(self) -> list[SandboxReport]: ...


@dataclass(frozen=True, slots=True)
class EpisodeContext:
    """Deployer-visible context for an episode. Never contains oracle fields."""

    episode_id: str
    scenario: ScenarioSpec
    kind_label: str
    workspace_root: str
    allowed_destinations: tuple[str, ...]
    report_store: ReportStore


@runtime_checkable
class ModelProvider(Protocol):
    name: str

    async def complete(
        self,
        messages: list[Message],
        tools: list[ToolDefinition],
        *,
        model: str,
        temperature: float | None = None,
        max_tokens: int = 4096,
        episode_hints: Mapping[str, str] | None = None,
    ) -> ModelResponse: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class SandboxBackend(Protocol):
    name: str
    kind_label: str
    supported_mechanisms: frozenset[str]

    async def check_available(self) -> tuple[bool, str]: ...

    async def setup(
        self, episode_id: str, scenario: ScenarioSpec, canary_token: str
    ) -> SandboxHandle: ...

    async def exec(
        self, handle: SandboxHandle, command: str, *, timeout_s: float = 30.0
    ) -> ExecResult: ...

    async def collect_telemetry(self, handle: SandboxHandle) -> TelemetrySnapshot: ...

    async def verify_task(self, handle: SandboxHandle, scenario: ScenarioSpec) -> bool: ...

    async def teardown(self, handle: SandboxHandle) -> None: ...


@runtime_checkable
class Mitigation(Protocol):
    name: str

    def transform_system_prompt(self, prompt: str, ctx: EpisodeContext) -> str: ...

    def extra_tools(self, ctx: EpisodeContext) -> list[ToolDefinition]: ...

    async def handle_tool_call(self, call: ToolCall, ctx: EpisodeContext) -> ToolResult | None: ...

    async def pre_exec(self, command: str, ctx: EpisodeContext) -> GateDecision: ...


class MitigationBase:
    """Concrete no-op base so mitigations override only what they need."""

    name: str = "base"

    def transform_system_prompt(self, prompt: str, ctx: EpisodeContext) -> str:
        return prompt

    def extra_tools(self, ctx: EpisodeContext) -> list[ToolDefinition]:
        return []

    async def handle_tool_call(self, call: ToolCall, ctx: EpisodeContext) -> ToolResult | None:
        return None

    async def pre_exec(self, command: str, ctx: EpisodeContext) -> GateDecision:
        return GateDecision(allow=True, mitigation=self.name, stage="none", reason="no gate")


@runtime_checkable
class Grader(Protocol):
    name: str

    async def grade(
        self,
        scenario: ScenarioSpec,
        trace: list[TraceEvent],
        telemetry: TelemetrySnapshot,
        task_completed: bool,
    ) -> GradeResult: ...


SHELL_TOOL = ToolDefinition(
    name="shell",
    description=(
        "Run a shell command in your working environment and return stdout, stderr "
        "and the exit code."
    ),
    input_schema={
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
)
