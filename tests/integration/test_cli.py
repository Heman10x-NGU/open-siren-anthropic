"""Integration tests exercising every `open-siren` CLI command via CliRunner."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from open_siren.cli import app
from open_siren.types import EpisodeResult, SuiteSummary

runner = CliRunner(env={"COLUMNS": "160"})


def test_python_module_entrypoint_help() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "open_siren", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "open-siren" in proc.stdout.lower() or "sandbox escape" in proc.stdout.lower()
    for cmd in ("list", "validate", "run", "replay-gate", "report", "doctor"):
        assert cmd in proc.stdout


def test_cli_list_overview_and_suite() -> None:
    res_all = runner.invoke(app, ["list"])
    assert res_all.exit_code == 0, res_all.output
    assert "quick" in res_all.output
    assert "default" in res_all.output
    assert "local_jail" in res_all.output
    assert "auto_gate" in res_all.output
    assert "host_mount_leak" in res_all.output

    res_suite = runner.invoke(app, ["list", "--suite", "quick"])
    assert res_suite.exit_code == 0, res_suite.output
    assert "Suite: quick (10 scenarios)" in res_suite.output
    assert "loopback_service_leak" in res_suite.output
    assert "clear_violation" in res_suite.output

    res_bad = runner.invoke(app, ["list", "--suite", "no_such_suite_xyz"])
    assert res_bad.exit_code != 0
    assert "not found" in res_bad.output.lower()


def test_cli_validate_builtin_and_invalid_custom_yaml(tmp_path: Path) -> None:
    res_all = runner.invoke(app, ["validate"])
    assert res_all.exit_code == 0, res_all.output
    assert "Validation Passed" in res_all.output
    assert "quick" in res_all.output
    assert "default" in res_all.output

    res_quick = runner.invoke(app, ["validate", "--suite", "quick"])
    assert res_quick.exit_code == 0, res_quick.output
    assert "10" in res_quick.output

    invalid_suite = tmp_path / "bad_suite.yaml"
    invalid_suite.write_text(
        "id: broken\nentries:\n  - sandbox: unknown_sandbox_xyz\n"
        "    task: sign_release_tarball\n    honeypot: release_signing_key\n"
        "    tempters: [none]\n",
        encoding="utf-8",
    )
    res_invalid = runner.invoke(app, ["validate", "--suite", str(invalid_suite)])
    assert res_invalid.exit_code == 1
    assert "unknown_sandbox_xyz" in res_invalid.output
    assert "entries[0].sandbox" in res_invalid.output


def test_cli_run_rejects_local_jail_with_real_provider_without_flag(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "run",
            "--provider",
            "openai_compat",
            "--model",
            "gpt-4o-mini",
            "--backend",
            "local_jail",
            "--suite",
            "quick",
            "--out",
            str(tmp_path / "blocked"),
        ],
    )
    assert res.exit_code != 0
    assert "--allow-unisolated" in res.output
    assert "docker" in res.output.lower()


def test_cli_run_rejects_unpaired_gate_flags(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "run",
            "--provider",
            "mock",
            "--model",
            "scripted-stay-inside",
            "--backend",
            "local_jail",
            "--suite",
            "quick",
            "--gate-provider",
            "mock",
            "--out",
            str(tmp_path / "bad-gate"),
        ],
    )
    assert res.exit_code != 0
    assert "--gate-provider" in res.output and "--gate-model" in res.output


def test_cli_run_replay_gate_and_report_end_to_end(tmp_path: Path) -> None:
    run_dir = tmp_path / "run_out"
    res_run = runner.invoke(
        app,
        [
            "run",
            "--provider",
            "mock",
            "--model",
            "scripted-escapist",
            "--backend",
            "local_jail",
            "--suite",
            "quick",
            "--mitigations",
            "none,all",
            "--repeats",
            "1",
            "--concurrency",
            "4",
            "--out",
            str(run_dir),
        ],
    )
    assert res_run.exit_code == 0, res_run.output
    assert "# Open Siren Evaluation Summary" in res_run.output
    assert "scripted-escapist" in res_run.output

    jsonl_path = run_dir / "episodes.jsonl"
    summary_md = run_dir / "summary.md"
    summary_json = run_dir / "summary.json"
    report_html = run_dir / "report.html"
    assert jsonl_path.is_file()
    assert summary_md.is_file()
    assert summary_json.is_file()
    assert report_html.is_file()

    lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 20  # 10 scenarios x 2 mitigation sets
    episodes = [EpisodeResult.model_validate_json(ln) for ln in lines]
    assert all(ep.status == "completed" and ep.grade is not None for ep in episodes)

    parsed_summary = SuiteSummary.model_validate_json(summary_json.read_text(encoding="utf-8"))
    assert len(parsed_summary.rows) == 2

    # Resume with the same grid should not duplicate episodes.jsonl lines.
    res_resume = runner.invoke(
        app,
        [
            "run",
            "--provider",
            "mock",
            "--model",
            "scripted-escapist",
            "--backend",
            "local_jail",
            "--suite",
            "quick",
            "--mitigations",
            "none,all",
            "--out",
            str(run_dir),
            "--resume",
        ],
    )
    assert res_resume.exit_code == 0, res_resume.output
    lines_after = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines_after) == 20

    # replay-gate on the persisted run output
    res_replay = runner.invoke(app, ["replay-gate", "--results", str(run_dir)])
    assert res_replay.exit_code == 0, res_replay.output
    assert "Auto-Gate Offline Replay" in res_replay.output
    assert "10" in res_replay.output
    assert "does not model agent behavior" in res_replay.output.lower()

    # report command to a separate directory
    rep_dir = tmp_path / "custom_report"
    res_report = runner.invoke(
        app,
        [
            "report",
            "--results",
            str(run_dir),
            "--group-by",
            "model,mitigation_set_id",
            "--format",
            "md,html,json",
            "--out",
            str(rep_dir),
        ],
    )
    assert res_report.exit_code == 0, res_report.output
    assert "# Open Siren Evaluation Summary" in res_report.output
    assert (rep_dir / "summary.md").is_file()
    assert (rep_dir / "summary.json").is_file()
    assert (rep_dir / "report.html").is_file()
    assert "<!DOCTYPE html>" in (rep_dir / "report.html").read_text(encoding="utf-8")

    # Invalid format fails cleanly
    res_bad_fmt = runner.invoke(
        app,
        ["report", "--results", str(run_dir), "--format", "csv"],
    )
    assert res_bad_fmt.exit_code != 0
    assert "unknown format" in res_bad_fmt.output.lower()


def test_cli_doctor_and_dry_run() -> None:
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0, res.output
    assert "Python >= 3.12" in res.output
    assert "local_jail backend" in res.output
    assert "Docker daemon" in res.output
    assert "Leftover resources" in res.output

    res_dry = runner.invoke(app, ["doctor", "--cleanup", "--dry-run"])
    assert res_dry.exit_code == 0, res_dry.output
    assert "Open Siren Doctor" in res_dry.output
