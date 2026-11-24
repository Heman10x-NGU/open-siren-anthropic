"""Open Siren: agent sandbox escape propensity evaluation harness."""

from open_siren.grading import SirenGrader, load_results, summarize
from open_siren.mitigations import MitigationPipeline, parse_mitigation_sets, replay_commands
from open_siren.registry import (
    GRADER_REGISTRY,
    MITIGATION_REGISTRY,
    PROVIDER_REGISTRY,
    SANDBOX_REGISTRY,
)
from open_siren.runner import (
    BENCHMARK_CANARY_GUID,
    EpisodeRunner,
    EvalHarness,
    export_web_bundle,
    render_html,
    render_json,
    render_markdown,
    sanitize_episode_for_web,
)
from open_siren.sandboxes import (
    BwrapSandboxBackend,
    DockerSandboxBackend,
    LocalJailBackend,
    UnshareSandboxBackend,
    parse_strace_log,
)
from open_siren.scenarios import (
    TempterSearchPipeline,
    filter_scenarios,
    list_builtin_suites,
    load_suite,
)

__version__ = "0.2.0"

__all__ = [
    "BENCHMARK_CANARY_GUID",
    "BwrapSandboxBackend",
    "DockerSandboxBackend",
    "EpisodeRunner",
    "EvalHarness",
    "GRADER_REGISTRY",
    "LocalJailBackend",
    "MITIGATION_REGISTRY",
    "MitigationPipeline",
    "PROVIDER_REGISTRY",
    "SANDBOX_REGISTRY",
    "SirenGrader",
    "TempterSearchPipeline",
    "UnshareSandboxBackend",
    "__version__",
    "export_web_bundle",
    "filter_scenarios",
    "list_builtin_suites",
    "load_results",
    "load_suite",
    "parse_mitigation_sets",
    "parse_strace_log",
    "render_html",
    "render_json",
    "render_markdown",
    "replay_commands",
    "sanitize_episode_for_web",
    "summarize",
]
