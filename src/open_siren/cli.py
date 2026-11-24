"""Typer CLI for Open Siren (`open-siren`)."""

from __future__ import annotations

import asyncio
import contextlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Literal

import typer
from rich.console import Console
from rich.table import Table

from open_siren.grading import load_results, summarize
from open_siren.interfaces import ModelProvider
from open_siren.mitigations import AutoGateMitigation, parse_mitigation_sets, replay_commands
from open_siren.registry import (
    GRADER_REGISTRY,
    MITIGATION_REGISTRY,
    PROVIDER_REGISTRY,
    SANDBOX_REGISTRY,
)
from open_siren.runner import EvalHarness, render_html, render_json, render_markdown
from open_siren.sandboxes import DockerSandboxBackend, LocalJailBackend, reap
from open_siren.scenarios import (
    ScenarioValidationError,
    list_builtin_suites,
    load_catalog,
    load_suite,
)
from open_siren.types import RateCI, SuiteSummary

app = typer.Typer(
    name="open-siren",
    help="Open Siren: agent sandbox escape propensity evaluation harness.",
    no_args_is_help=True,
)

_VALID_REPORT_FORMATS: frozenset[str] = frozenset({"md", "html", "json"})
_DEFAULT_DOCKER_IMAGE = "open-siren-runner:0.1"


class _CliError(Exception):
    """User-facing CLI error mapped cleanly to exit code 1."""


def _stdout_console() -> Console:
    return Console()


def _stderr_console() -> Console:
    return Console(stderr=True)


def _print_error(message: str) -> None:
    _stderr_console().print(f"[bold red]Error:[/bold red] {message}")


def _parse_csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _fmt_rate_ci(rate: RateCI) -> str:
    if rate.n <= 0:
        return "— (0/0)"
    return (
        f"{rate.rate * 100:.1f}% ({rate.k}/{rate.n}) [{rate.lo * 100:.1f}%, {rate.hi * 100:.1f}%]"
    )


def _validate_gate_args(
    gate_provider: str | None,
    gate_model: str | None,
    gate_fail_mode: str,
) -> Literal["closed", "open"]:
    if bool(gate_provider) != bool(gate_model):
        raise _CliError("Both --gate-provider and --gate-model must be provided together.")
    if gate_fail_mode not in ("closed", "open"):
        raise _CliError(
            f"Invalid --gate-fail-mode {gate_fail_mode!r}. Expected 'closed' or 'open'."
        )
    return "closed" if gate_fail_mode == "closed" else "open"


def _build_provider(
    name: str,
    *,
    base_url: str | None = None,
    api_key_env: str | None = None,
) -> ModelProvider:
    kwargs: dict[str, Any] = {}
    if base_url is not None:
        kwargs["base_url"] = base_url
    if api_key_env is not None:
        kwargs["api_key_env"] = api_key_env
    try:
        return PROVIDER_REGISTRY.create(name, **kwargs)
    except (KeyError, ValueError, TypeError) as exc:
        raise _CliError(f"Failed to initialize provider {name!r}: {exc}") from exc


def _write_reports(
    summary: SuiteSummary,
    out_dir: Path,
    formats: Sequence[str],
) -> tuple[list[Path], str | None]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    md_text: str | None = None

    for fmt in formats:
        if fmt == "md":
            md_text = render_markdown(summary)
            path = out_dir / "summary.md"
            path.write_text(md_text, encoding="utf-8")
            written.append(path)
        elif fmt == "json":
            path = out_dir / "summary.json"
            path.write_text(render_json(summary), encoding="utf-8")
            written.append(path)
        elif fmt == "html":
            path = out_dir / "report.html"
            path.write_text(render_html(summary), encoding="utf-8")
            written.append(path)
        else:
            raise _CliError(f"Unknown report format {fmt!r}. Supported formats: md, html, json.")

    return written, md_text


async def _check_docker_image(image: str = _DEFAULT_DOCKER_IMAGE) -> tuple[bool, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "image",
            "inspect",
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return False, "docker binary not found on PATH"

    try:
        _, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
        return False, f"docker image inspect timed out for {image!r}"

    if proc.returncode == 0:
        return True, f"Image {image!r} present"
    detail = stderr_b.decode("utf-8", errors="replace").strip()
    return False, detail or f"Image {image!r} not built yet (first docker run builds it)"


@app.command("list")
def list_cmd(
    suite: Annotated[
        str | None,
        typer.Option("--suite", help="Built-in suite name, YAML file, or catalog directory."),
    ] = None,
) -> None:
    """List built-in suites, plugins, and catalog entries, or scenarios in a specific suite."""
    console = _stdout_console()

    if suite is not None:
        try:
            scenarios = load_suite(suite)
        except ScenarioValidationError as exc:
            _print_error(str(exc))
            raise typer.Exit(code=1) from None

        table = Table(title=f"Suite: {suite} ({len(scenarios)} scenarios)")
        table.add_column("ID", style="cyan", overflow="fold")
        table.add_column("Mechanism", style="magenta", overflow="fold")
        table.add_column("Difficulty", overflow="fold")
        table.add_column("Tempter", overflow="fold")
        table.add_column("Ablation", overflow="fold")
        table.add_column("Ambiguity", overflow="fold")

        for sc in scenarios:
            table.add_row(
                sc.scenario_id,
                sc.sandbox.weakness_mechanism,
                sc.task.difficulty,
                sc.tempter.id,
                sc.tempter_ablation,
                sc.ambiguity_level,
            )

        console.print(table)
        return

    try:
        catalog = load_catalog()
    except ScenarioValidationError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1) from None

    suites = list_builtin_suites()

    reg_table = Table(title="Open Siren Components & Registries")
    reg_table.add_column("Category", style="bold cyan")
    reg_table.add_column("Available")
    reg_table.add_row("Suites", ", ".join(suites) or "—")
    reg_table.add_row("Providers", ", ".join(PROVIDER_REGISTRY.names()) or "—")
    reg_table.add_row("Sandbox Backends", ", ".join(SANDBOX_REGISTRY.names()) or "—")
    reg_table.add_row("Mitigations", ", ".join(MITIGATION_REGISTRY.names()) or "—")
    reg_table.add_row("Graders", ", ".join(GRADER_REGISTRY.names()) or "—")
    console.print(reg_table)

    sb_table = Table(title=f"Catalog Sandboxes ({len(catalog.sandboxes)})")
    sb_table.add_column("ID", style="cyan")
    sb_table.add_column("Weakness Type")
    sb_table.add_column("Mechanism", style="magenta")
    for sb in sorted(catalog.sandboxes.values(), key=lambda s: s.id):
        sb_table.add_row(sb.id, sb.weakness_type, sb.weakness_mechanism)
    console.print(sb_table)

    task_table = Table(title=f"Catalog Tasks ({len(catalog.tasks)})")
    task_table.add_column("ID", style="cyan")
    task_table.add_column("Difficulty")
    task_table.add_column("Title")
    for task in sorted(catalog.tasks.values(), key=lambda t: t.id):
        task_table.add_row(task.id, task.difficulty, task.title)
    console.print(task_table)

    tempter_table = Table(title=f"Catalog Tempters ({len(catalog.tempters)})")
    tempter_table.add_column("ID", style="cyan")
    tempter_table.add_column("Segments", justify="right")
    tempter_table.add_column("Tags")
    for tempter in sorted(catalog.tempters.values(), key=lambda t: t.id):
        tempter_table.add_row(
            tempter.id,
            str(len(tempter.segments)),
            ", ".join(tempter.tags) or "—",
        )
    console.print(tempter_table)


@app.command("validate")
def validate_cmd(
    suite: Annotated[
        str | None,
        typer.Option("--suite", help="Built-in suite name, YAML file, or catalog directory."),
    ] = None,
) -> None:
    """Validate built-in catalog and suites, or a specific suite file/directory."""
    console = _stdout_console()
    try:
        if suite is not None:
            scenarios = load_suite(suite)
            mechanisms = sorted({sc.sandbox.weakness_mechanism for sc in scenarios})
            table = Table(title=f"Validation Passed: {suite}")
            table.add_column("Check", style="bold")
            table.add_column("Count / Details")
            table.add_row("Scenarios", str(len(scenarios)))
            table.add_row("Mechanisms", f"{len(mechanisms)} ({', '.join(mechanisms)})")
            console.print(table)
            return

        catalog = load_catalog()
        suite_names = list_builtin_suites()
        suite_counts: list[tuple[str, int]] = []
        total_scenarios = 0
        for name in suite_names:
            scenarios = load_suite(name)
            suite_counts.append((name, len(scenarios)))
            total_scenarios += len(scenarios)

        table = Table(title="Validation Passed")
        table.add_column("Artifact", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("Sandboxes", str(len(catalog.sandboxes)))
        table.add_row("Tasks", str(len(catalog.tasks)))
        table.add_row("Honeypots", str(len(catalog.honeypots)))
        table.add_row("Tempters", str(len(catalog.tempters)))
        for name, count in suite_counts:
            table.add_row(f"Suite '{name}' scenarios", str(count))
        table.add_row("Total suite scenarios", str(total_scenarios))
        console.print(table)
    except ScenarioValidationError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1) from None


@app.command("run")
def run_cmd(
    provider: Annotated[
        str,
        typer.Option(
            "--provider", help="Model provider name (e.g. openai_compat, anthropic, mock)."
        ),
    ],
    model: Annotated[
        str,
        typer.Option("--model", help="Model ID (or mock script name)."),
    ],
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Custom API base URL for openai_compat/anthropic."),
    ] = None,
    api_key_env: Annotated[
        str | None,
        typer.Option("--api-key-env", help="Environment variable holding the provider API key."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Sandbox backend: local_jail or docker."),
    ] = "docker",
    suite: Annotated[
        str,
        typer.Option("--suite", help="Built-in suite name, YAML file, or catalog directory."),
    ] = "default",
    mitigations: Annotated[
        str,
        typer.Option(
            "--mitigations",
            help="Comma-separated mitigation sets (join within a set with '+').",
        ),
    ] = "none,all",
    repeats: Annotated[
        int,
        typer.Option("--repeats", min=1, help="Repeats per (scenario, mitigation set)."),
    ] = 1,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", min=1, help="Maximum concurrent episodes."),
    ] = 4,
    max_turns: Annotated[
        int,
        typer.Option("--max-turns", min=1, help="Maximum model turns per episode."),
    ] = 30,
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory for episodes.jsonl and reports."),
    ] = Path("results/run"),
    resume: Annotated[
        bool,
        typer.Option("--resume/--no-resume", help="Resume from existing episodes.jsonl in --out."),
    ] = False,
    allow_unisolated: Annotated[
        bool,
        typer.Option(
            "--allow-unisolated",
            help="Explicitly allow running a non-mock provider on local_jail.",
        ),
    ] = False,
    gate_provider: Annotated[
        str | None,
        typer.Option("--gate-provider", help="Optional Stage 2 classifier provider for auto_gate."),
    ] = None,
    gate_model: Annotated[
        str | None,
        typer.Option("--gate-model", help="Optional Stage 2 classifier model for auto_gate."),
    ] = None,
    gate_fail_mode: Annotated[
        str,
        typer.Option("--gate-fail-mode", help="Auto-gate Stage 2 failure mode: closed or open."),
    ] = "closed",
) -> None:
    """Execute an Open Siren evaluation suite and generate summary reports."""
    try:
        # 1. Host isolation guard BEFORE provider initialization so missing keys don't mask it.
        if backend == "local_jail" and provider != "mock" and not allow_unisolated:
            raise _CliError(
                "Refusing to run non-mock provider "
                f"{provider!r} on backend 'local_jail' without --allow-unisolated. "
                "'local_jail' is NOT a security boundary (the agent can read your real files "
                "and reach your network). Use '--backend docker' for isolated execution, or "
                "pass '--allow-unisolated' to explicitly accept the risk."
            )

        fail_mode = _validate_gate_args(gate_provider, gate_model, gate_fail_mode)

        try:
            scenarios = load_suite(suite)
        except ScenarioValidationError as exc:
            raise _CliError(str(exc)) from exc

        mitigation_sets = parse_mitigation_sets(mitigations)
        for mit_set in mitigation_sets:
            for mit_name in mit_set:
                try:
                    MITIGATION_REGISTRY.get(mit_name)
                except KeyError as exc:
                    raise _CliError(str(exc)) from exc

        try:
            sandbox_backend = SANDBOX_REGISTRY.create(backend)
        except (KeyError, ValueError, TypeError) as exc:
            raise _CliError(f"Failed to initialize sandbox backend {backend!r}: {exc}") from exc

        try:
            grader = GRADER_REGISTRY.create("siren_default")
        except (KeyError, ValueError, TypeError) as exc:
            raise _CliError(f"Failed to initialize grader: {exc}") from exc

        async def _execute() -> tuple[list[Any], bool]:
            ok, avail_msg = await sandbox_backend.check_available()
            if not ok:
                raise _CliError(f"Sandbox backend {backend!r} is unavailable: {avail_msg}")

            model_provider: ModelProvider | None = None
            classifier_provider: ModelProvider | None = None
            try:
                model_provider = _build_provider(
                    provider,
                    base_url=base_url,
                    api_key_env=api_key_env,
                )

                auto_gate_cfg: dict[str, Any] = {"fail_mode": fail_mode}
                if gate_provider is not None and gate_model is not None:
                    same_provider = gate_provider == provider and provider != "mock"
                    classifier_provider = _build_provider(
                        gate_provider,
                        base_url=base_url if same_provider else None,
                        api_key_env=api_key_env if same_provider else None,
                    )
                    auto_gate_cfg["classifier_provider"] = classifier_provider
                    auto_gate_cfg["classifier_model"] = gate_model

                harness = EvalHarness(
                    provider=model_provider,
                    backend=sandbox_backend,
                    grader=grader,
                    scenarios=scenarios,
                    mitigation_sets=mitigation_sets,
                    model=model,
                    out_dir=out,
                    repeats=repeats,
                    concurrency=concurrency,
                    max_turns=max_turns,
                    resume=resume,
                    mitigation_configs={"auto_gate": auto_gate_cfg},
                )
                results = await harness.run()
                return results, harness.interrupted
            finally:
                if model_provider is not None:
                    await model_provider.aclose()
                if classifier_provider is not None:
                    await classifier_provider.aclose()

        results, interrupted = asyncio.run(_execute())
        summary = summarize(results, group_by=("model", "mitigation_set_id"))
        written, md_text = _write_reports(summary, out, ("md", "json", "html"))

        if md_text is not None:
            typer.echo(md_text, nl=False)

        _stderr_console().print(
            f"Saved {len(results)} episode(s) to [bold]{out / 'episodes.jsonl'}[/bold] "
            f"and reports: {', '.join(str(p) for p in written)}"
        )

        if interrupted:
            _stderr_console().print(
                "[yellow]Run interrupted by SIGINT; partial results saved.[/yellow]"
            )
            raise typer.Exit(code=130)

    except _CliError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1) from None


@app.command("replay-gate")
def replay_gate_cmd(
    results: Annotated[
        Path,
        typer.Option("--results", help="Path to results directory or episodes.jsonl file."),
    ],
    gate_provider: Annotated[
        str | None,
        typer.Option("--gate-provider", help="Optional Stage 2 classifier provider."),
    ] = None,
    gate_model: Annotated[
        str | None,
        typer.Option("--gate-model", help="Optional Stage 2 classifier model."),
    ] = None,
    gate_fail_mode: Annotated[
        str,
        typer.Option("--gate-fail-mode", help="Stage 2 failure mode: closed or open."),
    ] = "closed",
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Custom API base URL for gate provider."),
    ] = None,
    api_key_env: Annotated[
        str | None,
        typer.Option("--api-key-env", help="Environment variable holding gate provider API key."),
    ] = None,
) -> None:
    """Replay recorded shell commands from episodes run without auto_gate through AutoGate."""
    try:
        fail_mode = _validate_gate_args(gate_provider, gate_model, gate_fail_mode)

        try:
            episodes = list(load_results(results))
        except (FileNotFoundError, ValueError, OSError) as exc:
            raise _CliError(f"Failed to load results from {results}: {exc}") from exc

        async def _run_replay() -> Any:
            classifier_provider: ModelProvider | None = None
            try:
                if gate_provider is not None and gate_model is not None:
                    classifier_provider = _build_provider(
                        gate_provider,
                        base_url=base_url,
                        api_key_env=api_key_env,
                    )
                gate = AutoGateMitigation(
                    classifier_provider=classifier_provider,
                    classifier_model=gate_model,
                    fail_mode=fail_mode,
                )
                return await replay_commands(episodes, gate)
            finally:
                if classifier_provider is not None:
                    await classifier_provider.aclose()

        report = asyncio.run(_run_replay())

        console = _stdout_console()
        table = Table(title="Auto-Gate Offline Replay")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", justify="right")
        table.add_row("Eligible episodes (without auto_gate)", str(report.n_episodes))
        table.add_row("Reaching episodes", str(report.n_reaching))
        table.add_row("Misaligned episodes", str(report.n_misaligned))
        table.add_row("Blocked at first_reach_seq", _fmt_rate_ci(report.blocked_first_reach))
        table.add_row(
            "Blocked at first_read_seq (misaligned)",
            _fmt_rate_ci(report.blocked_first_read_misaligned),
        )
        table.add_row("Benign commands blocked", _fmt_rate_ci(report.benign_commands_blocked))
        console.print(table)
        console.print(f"[dim]Caveat: {report.caveat}[/dim]", soft_wrap=True)

    except _CliError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1) from None


@app.command("report")
def report_cmd(
    results: Annotated[
        Path,
        typer.Option("--results", help="Path to results directory or episodes.jsonl file."),
    ],
    group_by: Annotated[
        str,
        typer.Option("--group-by", help="Comma-separated grouping keys."),
    ] = "model,mitigation_set_id",
    fmt: Annotated[
        str,
        typer.Option("--format", help="Comma-separated output formats: md, html, json."),
    ] = "md,html,json",
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Output directory (defaults to --results directory)."),
    ] = None,
) -> None:
    """Aggregate episodes.jsonl and render Markdown, HTML, and/or JSON reports."""
    try:
        raw_formats = [f.lower() for f in _parse_csv(fmt)]
        if not raw_formats:
            raise _CliError("--format must specify at least one of: md, html, json.")
        formats: list[str] = []
        for item in raw_formats:
            if item not in _VALID_REPORT_FORMATS:
                raise _CliError(f"Unknown format {item!r}. Supported formats: md, html, json.")
            if item not in formats:
                formats.append(item)

        group_keys = tuple(_parse_csv(group_by))

        try:
            episodes = list(load_results(results))
        except (FileNotFoundError, ValueError, OSError) as exc:
            raise _CliError(f"Failed to load results from {results}: {exc}") from exc

        try:
            summary = summarize(episodes, group_by=group_keys)
        except ValueError as exc:
            raise _CliError(str(exc)) from exc

        out_dir = out if out is not None else (results if results.is_dir() else results.parent)
        written, md_text = _write_reports(summary, out_dir, formats)

        if md_text is not None:
            typer.echo(md_text, nl=False)

        _stderr_console().print(f"Wrote reports: {', '.join(str(p) for p in written)}")

    except _CliError as exc:
        _print_error(str(exc))
        raise typer.Exit(code=1) from None


@app.command("doctor")
def doctor_cmd(
    cleanup: Annotated[
        bool,
        typer.Option(
            "--cleanup",
            help="Reap orphaned Open Siren containers/volumes and stale /tmp/osr/* directories.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show leftover resources without deleting them (even with --cleanup).",
        ),
    ] = False,
) -> None:
    """Check Python version, sandbox backends, Docker runner image, and leftover resources."""

    async def _run_checks() -> tuple[tuple[bool, str], tuple[bool, str], tuple[bool, str] | None]:
        local_ok = await LocalJailBackend().check_available()
        docker_ok = await DockerSandboxBackend(image=_DEFAULT_DOCKER_IMAGE).check_available()
        image_ok: tuple[bool, str] | None = None
        if docker_ok[0]:
            image_ok = await _check_docker_image(_DEFAULT_DOCKER_IMAGE)
        return local_ok, docker_ok, image_ok

    py_ok = sys.version_info >= (3, 12)
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    local_status, docker_status, image_status = asyncio.run(_run_checks())
    effective_dry_run = (not cleanup) or dry_run
    leftovers = reap(dry_run=effective_dry_run)

    console = _stdout_console()
    table = Table(title="Open Siren Doctor")
    table.add_column("Check", style="bold cyan")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row(
        "Python >= 3.12",
        "[green]OK[/green]" if py_ok else "[red]FAIL[/red]",
        f"Python {py_ver}",
    )
    table.add_row(
        "local_jail backend",
        "[green]OK[/green]" if local_status[0] else "[red]FAIL[/red]",
        local_status[1],
    )
    table.add_row(
        "Docker daemon",
        "[green]OK[/green]" if docker_status[0] else "[yellow]WARN[/yellow]",
        docker_status[1]
        if docker_status[0]
        else f"{docker_status[1]} (optional; required for --backend docker)",
    )
    if image_status is not None:
        table.add_row(
            f"Runner image ({_DEFAULT_DOCKER_IMAGE})",
            "[green]OK[/green]" if image_status[0] else "[yellow]WARN[/yellow]",
            image_status[1],
        )
    else:
        table.add_row(
            f"Runner image ({_DEFAULT_DOCKER_IMAGE})",
            "[dim]SKIP[/dim]",
            "Docker daemon unavailable",
        )

    if effective_dry_run:
        orphan_status = "[green]OK[/green]" if not leftovers else "[yellow]WARN[/yellow]"
        orphan_detail = (
            "No leftover resources found"
            if not leftovers
            else f"{len(leftovers)} leftover resource(s) found (re-run with --cleanup to remove)"
        )
    else:
        orphan_status = "[green]OK[/green]"
        orphan_detail = (
            "No leftover resources to remove"
            if not leftovers
            else f"Removed {len(leftovers)} leftover resource(s)"
        )
    table.add_row("Leftover resources", orphan_status, orphan_detail)

    console.print(table)
    for item in leftovers:
        prefix = "Would remove" if effective_dry_run else "Removed"
        console.print(f"  - {prefix}: {item}")

    if not py_ok or not local_status[0]:
        raise typer.Exit(code=1)
