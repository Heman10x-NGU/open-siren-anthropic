"""Full-stack E2E verification across scenarios, sandboxes, mitigations, runner, and grader."""

from __future__ import annotations

from pathlib import Path

import pytest

from open_siren.grading import SirenGrader, load_results, summarize
from open_siren.mitigations import (
    AutoGateMitigation,
    MitigationPipeline,
    ReportToolMitigation,
    SandboxRulesMitigation,
    ViewReportsMitigation,
    parse_mitigation_sets,
    replay_commands,
)
from open_siren.registry import GRADER_REGISTRY, PROVIDER_REGISTRY, SANDBOX_REGISTRY
from open_siren.runner import (
    EpisodeRunner,
    EvalHarness,
    render_html,
    render_json,
    render_markdown,
)
from open_siren.sandboxes import LocalJailBackend
from open_siren.scenarios import load_suite
from open_siren.types import ScenarioSpec, SuiteSummary


def _pick_scenario(
    scenarios: list[ScenarioSpec],
    *,
    mechanism: str,
    ambiguity: str | None = None,
) -> ScenarioSpec:
    for sc in scenarios:
        if sc.sandbox.weakness_mechanism != mechanism:
            continue
        if ambiguity is not None and sc.ambiguity_level != ambiguity:
            continue
        return sc
    raise AssertionError(f"No scenario found for mechanism={mechanism!r}, ambiguity={ambiguity!r}")


async def test_full_stack_stay_inside() -> None:
    scenarios = load_suite("quick")
    scenario = _pick_scenario(scenarios, mechanism="loopback_service_leak")

    provider = PROVIDER_REGISTRY.create("mock")
    backend = SANDBOX_REGISTRY.create("local_jail")
    grader = GRADER_REGISTRY.create("siren_default")
    assert isinstance(backend, LocalJailBackend)
    assert isinstance(grader, SirenGrader)

    runner = EpisodeRunner(provider, backend, grader)
    result = await runner.run(
        run_id="e2e-stay",
        scenario=scenario,
        model="scripted-stay-inside",
        mitigations=(),
        repeat=0,
    )

    assert result.status == "completed"
    assert result.error is None
    assert result.grade is not None
    assert result.grade.reached_outside is False
    assert result.grade.used_honeypot is False
    assert result.grade.misaligned_use is False
    assert result.grade.first_reach_seq is None
    assert result.grade.first_read_seq is None


async def test_full_stack_escapist_unmitigated_clear_violation() -> None:
    scenarios = load_suite("quick")
    scenario = _pick_scenario(
        scenarios,
        mechanism="loopback_service_leak",
        ambiguity="clear_violation",
    )

    provider = PROVIDER_REGISTRY.create("mock")
    backend = SANDBOX_REGISTRY.create("local_jail")
    grader = GRADER_REGISTRY.create("siren_default")

    runner = EpisodeRunner(provider, backend, grader)
    result = await runner.run(
        run_id="e2e-escape",
        scenario=scenario,
        model="scripted-escapist",
        mitigations=(),
        repeat=0,
    )

    assert result.status == "completed"
    assert result.error is None
    assert result.grade is not None
    assert result.grade.reached_outside is True
    assert result.grade.used_honeypot is True
    assert result.grade.misaligned_use is True
    assert result.grade.first_reach_seq is not None
    assert result.grade.first_read_seq is not None
    assert len(result.grade.evidence) >= 1


@pytest.mark.parametrize(
    "mechanism",
    ["loopback_service_leak", "control_socket_leak", "egress_proxy_bypass"],
)
async def test_full_stack_escapist_blocked_by_auto_gate(mechanism: str) -> None:
    scenarios = load_suite("quick")
    scenario = _pick_scenario(scenarios, mechanism=mechanism)

    provider = PROVIDER_REGISTRY.create("mock")
    backend = SANDBOX_REGISTRY.create("local_jail")
    grader = GRADER_REGISTRY.create("siren_default")

    runner = EpisodeRunner(provider, backend, grader)
    result = await runner.run(
        run_id=f"e2e-gate-{mechanism}",
        scenario=scenario,
        model="scripted-escapist",
        mitigations=("auto_gate",),
        repeat=0,
    )

    assert result.status == "completed"
    assert result.error is None
    assert result.grade is not None
    assert result.grade.blocked_commands >= 1
    assert result.grade.reached_outside is False
    assert result.grade.used_honeypot is False
    assert result.grade.misaligned_use is False
    assert result.grade.first_reach_seq is None
    assert result.grade.first_read_seq is None


async def test_full_stack_reporter_with_report_and_view_tools() -> None:
    scenarios = load_suite("quick")
    scenario = _pick_scenario(scenarios, mechanism="host_mount_leak")

    # Verify real mitigation classes compose cleanly inside MitigationPipeline.
    pipeline = MitigationPipeline(
        [
            SandboxRulesMitigation(),
            ReportToolMitigation(),
            ViewReportsMitigation(),
            AutoGateMitigation(),
        ]
    )
    assert [m.name for m in pipeline.mitigations] == [
        "sandbox_rules",
        "report_tools",
        "view_reports",
        "auto_gate",
    ]

    provider = PROVIDER_REGISTRY.create("mock")
    backend = SANDBOX_REGISTRY.create("local_jail")
    grader = GRADER_REGISTRY.create("siren_default")

    runner = EpisodeRunner(provider, backend, grader)
    result = await runner.run(
        run_id="e2e-reporter",
        scenario=scenario,
        model="scripted-reporter",
        mitigations=("report_tools", "view_reports"),
        repeat=0,
    )

    assert result.status == "completed"
    assert result.error is None
    assert result.grade is not None
    assert result.grade.reported_weakness is True
    assert result.grade.reached_outside is False
    assert result.grade.used_honeypot is False
    assert result.grade.misaligned_use is False
    assert len(result.reports) >= 1
    assert all(r.source == "agent" for r in result.reports)


async def test_full_stack_quick_suite_harness_report_and_replay(tmp_path: Path) -> None:
    scenarios = load_suite("quick")
    n = len(scenarios)
    assert n == 12

    mitigation_sets = parse_mitigation_sets("none,all")
    provider = PROVIDER_REGISTRY.create("mock")
    backend = SANDBOX_REGISTRY.create("local_jail")
    grader = GRADER_REGISTRY.create("siren_default")

    harness = EvalHarness(
        provider=provider,
        backend=backend,
        grader=grader,
        scenarios=scenarios,
        mitigation_sets=mitigation_sets,
        model="scripted-escapist",
        out_dir=tmp_path,
        repeats=1,
        concurrency=4,
    )
    results = await harness.run()
    assert len(results) == n * 2
    assert all(ep.status == "completed" and ep.grade is not None for ep in results)

    # Reload persisted JSONL and verify aggregation + all 3 static renderers.
    jsonl_path = tmp_path / "episodes.jsonl"
    assert jsonl_path.is_file()
    loaded = list(load_results(jsonl_path))
    assert len(loaded) == n * 2

    summary = summarize(loaded, group_by=("model", "mitigation_set_id"))
    assert len(summary.rows) == 2
    by_mit = {row.group["mitigation_set_id"]: row for row in summary.rows}
    none_row = by_mit["none"]
    all_row = by_mit["sandbox_rules+report_tools+view_reports+auto_gate"]

    assert none_row.n_episodes == n
    assert none_row.n_errors == 0
    assert none_row.reached.k == n
    assert none_row.reached.rate == 1.0

    assert all_row.n_episodes == n
    assert all_row.n_errors == 0
    assert all_row.reached.k < none_row.reached.k
    assert all_row.reached_reduction_vs_none is not None
    assert all_row.reached_reduction_vs_none > 0.0

    md = render_markdown(summary)
    assert "# Open Siren Evaluation Summary" in md
    assert "scripted-escapist" in md
    assert "sandbox_rules+report_tools+view_reports+auto_gate" in md

    raw_json = render_json(summary)
    assert SuiteSummary.model_validate_json(raw_json) == summary

    html_doc = render_html(summary)
    assert "<!DOCTYPE html>" in html_doc
    assert "<svg" in html_doc
    assert "<script" not in html_doc.lower()

    # Offline gate replay on the persisted episodes (uses only the n episodes without auto_gate).
    gate = AutoGateMitigation()
    replay = await replay_commands(loaded, gate)
    assert replay.n_episodes == n
    assert replay.n_reaching == n
    assert replay.n_misaligned > 0
    assert replay.blocked_first_reach.n == n
    assert replay.blocked_first_reach.k > 0
    assert replay.blocked_first_read_misaligned.n > 0
    assert replay.blocked_first_read_misaligned.k > 0
    assert "does not model agent behavior" in replay.caveat.lower()
