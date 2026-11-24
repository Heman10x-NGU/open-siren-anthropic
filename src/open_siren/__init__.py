"""Open Siren: agent sandbox escape propensity evaluation harness."""

from open_siren.grading import SirenGrader, load_results, summarize
from open_siren.mitigations import MitigationPipeline, parse_mitigation_sets, replay_commands
from open_siren.registry import (
    GRADER_REGISTRY,
    MITIGATION_REGISTRY,
    PROVIDER_REGISTRY,
    SANDBOX_REGISTRY,
)
from open_siren.runner import EpisodeRunner, EvalHarness, render_html, render_json, render_markdown
from open_siren.scenarios import filter_scenarios, list_builtin_suites, load_suite

__version__ = "0.1.0"

__all__ = [
    "EpisodeRunner",
    "EvalHarness",
    "GRADER_REGISTRY",
    "MITIGATION_REGISTRY",
    "MitigationPipeline",
    "PROVIDER_REGISTRY",
    "SANDBOX_REGISTRY",
    "SirenGrader",
    "__version__",
    "filter_scenarios",
    "list_builtin_suites",
    "load_results",
    "load_suite",
    "parse_mitigation_sets",
    "render_html",
    "render_json",
    "render_markdown",
    "replay_commands",
    "summarize",
]
