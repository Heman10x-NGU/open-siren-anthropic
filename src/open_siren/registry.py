"""Lazy, plugin-capable registries for providers, sandboxes, mitigations, and graders."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from importlib import metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from open_siren.interfaces import Grader, Mitigation, ModelProvider, SandboxBackend


def _load_dotted(dotted: str) -> Callable[..., Any]:
    module_name, sep, attr_name = dotted.partition(":")
    if not sep or not module_name or not attr_name:
        raise ValueError(f"Invalid dotted target {dotted!r}; expected 'module.path:AttrName'")
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


class Registry[T]:
    """Generic registry with lookup order: programmatic > builtin (lazy) > entry points."""

    def __init__(
        self,
        kind: str,
        entry_point_group: str,
        builtins: Mapping[str, str],
    ) -> None:
        self.kind = kind
        self.entry_point_group = entry_point_group
        self._builtins: dict[str, str] = dict(builtins)
        self._registered: dict[str, Callable[..., T]] = {}

    def register[F: Callable[..., Any]](self, name: str) -> Callable[[F], F]:
        """Decorator to register a factory under `name`. Duplicate programmatic names fail."""

        def decorator(factory: F) -> F:
            if name in self._registered:
                raise ValueError(f"{self.kind} {name!r} is already registered")
            self._registered[name] = factory
            return factory

        return decorator

    def _entry_points(self) -> dict[str, metadata.EntryPoint]:
        eps = metadata.entry_points(group=self.entry_point_group)
        return {ep.name: ep for ep in eps}

    def names(self) -> list[str]:
        all_names = set(self._registered) | set(self._builtins) | set(self._entry_points())
        return sorted(all_names)

    def get(self, name: str) -> Callable[..., T]:
        if name in self._registered:
            return self._registered[name]

        if name in self._builtins:
            target = self._builtins[name]
            try:
                return _load_dotted(target)
            except (ImportError, AttributeError) as exc:
                available = ", ".join(self.names())
                raise KeyError(
                    f"Builtin {self.kind} {name!r} ({target}) could not be loaded: {exc}. "
                    f"Known {self.kind}s: [{available}]"
                ) from exc

        eps = self._entry_points()
        if name in eps:
            try:
                return eps[name].load()
            except (ImportError, AttributeError) as exc:
                available = ", ".join(self.names())
                raise KeyError(
                    f"Entry-point {self.kind} {name!r} could not be loaded: {exc}. "
                    f"Known {self.kind}s: [{available}]"
                ) from exc

        available = ", ".join(self.names())
        raise KeyError(f"Unknown {self.kind} {name!r}. Available {self.kind}s: [{available}]")

    def create(self, name: str, /, *args: Any, **config: Any) -> T:
        factory = self.get(name)
        return factory(*args, **config)


PROVIDER_REGISTRY: Registry[ModelProvider] = Registry(
    "provider",
    "open_siren.providers",
    {
        "openai_compat": "open_siren.providers.openai_compat:OpenAICompatProvider",
        "anthropic": "open_siren.providers.anthropic_provider:AnthropicProvider",
        "mock": "open_siren.providers.mock_provider:ScriptedProvider",
    },
)

SANDBOX_REGISTRY: Registry[SandboxBackend] = Registry(
    "sandbox",
    "open_siren.sandboxes",
    {
        "local_jail": "open_siren.sandboxes.local_jail:LocalJailBackend",
        "docker": "open_siren.sandboxes.docker_sandbox:DockerSandboxBackend",
        "bwrap": "open_siren.sandboxes.nested_linux:BwrapSandboxBackend",
        "unshare": "open_siren.sandboxes.nested_linux:UnshareSandboxBackend",
    },
)

MITIGATION_REGISTRY: Registry[Mitigation] = Registry(
    "mitigation",
    "open_siren.mitigations",
    {
        "sandbox_rules": "open_siren.mitigations.sandbox_rules:SandboxRulesMitigation",
        "report_tools": "open_siren.mitigations.report_tools:ReportToolMitigation",
        "view_reports": "open_siren.mitigations.report_tools:ViewReportsMitigation",
        "auto_gate": "open_siren.mitigations.auto_gate:AutoGateMitigation",
    },
)

GRADER_REGISTRY: Registry[Grader] = Registry(
    "grader",
    "open_siren.graders",
    {
        "siren_default": "open_siren.grading.grader:SirenGrader",
    },
)
