"""Concurrent evaluation harness with single-writer JSONL persistence, resume, and SIGINT."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import signal
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from open_siren.interfaces import Grader, ModelProvider, SandboxBackend
from open_siren.mitigations.presets import canonicalize_mitigations, mitigation_set_id
from open_siren.runner.episode import EpisodeRunner
from open_siren.types import EpisodeResult, ScenarioSpec

logger = logging.getLogger(__name__)

ResumeKey = tuple[str, str, str, str, int]


def _resume_key(result: EpisodeResult) -> ResumeKey:
    return (
        result.scenario.scenario_id,
        result.provider,
        result.model,
        result.mitigation_set_id,
        result.repeat,
    )


def _load_resumed_results(path: Path) -> tuple[dict[ResumeKey, EpisodeResult], set[ResumeKey]]:
    """Read prior episodes.jsonl, skipping a truncated final line and retrying error episodes."""
    if not path.exists():
        return {}, set()

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    non_empty = [(idx + 1, line) for idx, line in enumerate(raw_lines) if line.strip()]

    resumed_by_key: dict[ResumeKey, EpisodeResult] = {}
    completed_keys: set[ResumeKey] = set()

    for pos, (line_no, line) in enumerate(non_empty):
        is_last = pos == len(non_empty) - 1
        try:
            result = EpisodeResult.model_validate_json(line)
        except (ValidationError, ValueError) as exc:
            if is_last:
                logger.warning(
                    "Skipping truncated or invalid final line %d in %s: %s",
                    line_no,
                    path,
                    exc,
                )
                continue
            logger.warning(
                "Skipping malformed line %d in %s: %s",
                line_no,
                path,
                exc,
            )
            continue

        key = _resume_key(result)
        if result.status != "error":
            completed_keys.add(key)
            resumed_by_key[key] = result

    return resumed_by_key, completed_keys


def _ensure_trailing_newline(path: Path) -> None:
    """Ensure an existing non-empty file ends with a newline before appending JSONL records."""
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open("rb+") as fh:
        fh.seek(-1, os.SEEK_END)
        if fh.read(1) != b"\n":
            fh.write(b"\n")
            fh.flush()


class EvalHarness:
    """Runs a grid of (scenario, mitigation_set, repeat) with bounded concurrency and JSONL logs."""

    def __init__(
        self,
        *,
        provider: ModelProvider,
        backend: SandboxBackend,
        grader: Grader,
        scenarios: Sequence[ScenarioSpec],
        mitigation_sets: Sequence[Sequence[str]],
        model: str,
        out_dir: Path | str,
        repeats: int = 1,
        concurrency: int = 4,
        max_turns: int = 30,
        episode_timeout_s: float = 600.0,
        exec_timeout_s: float = 30.0,
        temperature: float | None = None,
        max_tokens: int = 4096,
        resume: bool = False,
        run_id: str | None = None,
        mitigation_configs: Mapping[str, Mapping[str, Any]] | None = None,
        on_episode_done: Callable[[EpisodeResult], None] | None = None,
    ) -> None:
        if repeats < 1:
            raise ValueError(f"repeats must be >= 1, got {repeats}")
        if concurrency < 1:
            raise ValueError(f"concurrency must be >= 1, got {concurrency}")

        self.provider = provider
        self.backend = backend
        self.grader = grader
        self.scenarios = tuple(scenarios)
        self.mitigation_sets = tuple(tuple(ms) for ms in mitigation_sets)
        self.model = model
        self.out_dir = Path(out_dir)
        self.results_path = self.out_dir / "episodes.jsonl"
        self.repeats = repeats
        self.concurrency = concurrency
        self.max_turns = max_turns
        self.episode_timeout_s = episode_timeout_s
        self.exec_timeout_s = exec_timeout_s
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.resume = resume
        self.run_id = run_id or (
            f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
        )
        self.mitigation_configs: dict[str, dict[str, Any]] = {
            k: dict(v) for k, v in (mitigation_configs or {}).items()
        }
        self.on_episode_done = on_episode_done
        self.interrupted = False

    def _build_canonical_sets(self) -> list[tuple[tuple[str, ...], str]]:
        canonical_sets: list[tuple[tuple[str, ...], str]] = []
        seen: set[str] = set()
        for raw_set in self.mitigation_sets:
            canonical = canonicalize_mitigations(raw_set)
            set_id = mitigation_set_id(canonical)
            if set_id not in seen:
                seen.add(set_id)
                canonical_sets.append((canonical, set_id))
        return canonical_sets

    async def _writer_loop(
        self,
        queue: asyncio.Queue[EpisodeResult | None],
        path: Path,
    ) -> None:
        with path.open("a", encoding="utf-8") as fh:
            while True:
                item = await queue.get()
                try:
                    if item is None:
                        return
                    fh.write(item.model_dump_json() + "\n")
                    fh.flush()
                finally:
                    queue.task_done()

    async def run(self) -> list[EpisodeResult]:
        """Execute all pending episodes and return resumed + newly completed results."""
        self.interrupted = False
        self.out_dir.mkdir(parents=True, exist_ok=True)

        resumed_by_key: dict[ResumeKey, EpisodeResult] = {}
        completed_keys: set[ResumeKey] = set()
        if self.resume and self.results_path.exists():
            resumed_by_key, completed_keys = _load_resumed_results(self.results_path)

        canonical_sets = self._build_canonical_sets()
        pending: list[tuple[ScenarioSpec, tuple[str, ...], int]] = []
        planned_keys: list[ResumeKey] = []

        for scenario in self.scenarios:
            for canonical_mits, set_id in canonical_sets:
                for repeat in range(self.repeats):
                    key: ResumeKey = (
                        scenario.scenario_id,
                        self.provider.name,
                        self.model,
                        set_id,
                        repeat,
                    )
                    planned_keys.append(key)
                    if key not in completed_keys:
                        pending.append((scenario, canonical_mits, repeat))

        resumed_results = [resumed_by_key[k] for k in planned_keys if k in resumed_by_key]
        if not pending:
            return resumed_results

        _ensure_trailing_newline(self.results_path)

        runner = EpisodeRunner(
            self.provider,
            self.backend,
            self.grader,
            max_turns=self.max_turns,
            episode_timeout_s=self.episode_timeout_s,
            exec_timeout_s=self.exec_timeout_s,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            mitigation_configs=self.mitigation_configs,
        )

        queue: asyncio.Queue[EpisodeResult | None] = asyncio.Queue()
        writer_task = asyncio.create_task(self._writer_loop(queue, self.results_path))
        semaphore = asyncio.Semaphore(self.concurrency)
        stop_event = asyncio.Event()
        new_results: list[EpisodeResult] = []
        episode_tasks: list[asyncio.Task[EpisodeResult | None]] = []

        async def _run_one(
            scenario: ScenarioSpec,
            mitigations: tuple[str, ...],
            repeat: int,
        ) -> EpisodeResult | None:
            async with semaphore:
                if stop_event.is_set():
                    return None
                result = await runner.run(
                    run_id=self.run_id,
                    scenario=scenario,
                    model=self.model,
                    mitigations=mitigations,
                    repeat=repeat,
                )
                await queue.put(result)
                new_results.append(result)
                if self.on_episode_done is not None:
                    self.on_episode_done(result)
                return result

        loop = asyncio.get_running_loop()
        sigint_installed = False
        sigint_count = 0

        def _handle_sigint() -> None:
            nonlocal sigint_count
            sigint_count += 1
            if sigint_count == 1:
                self.interrupted = True
                stop_event.set()
                logger.warning(
                    "SIGINT received; cancelling in-flight episodes and tearing down sandboxes. "
                    "Press Ctrl-C again to force exit."
                )
                for task in episode_tasks:
                    if not task.done():
                        task.cancel()
            else:
                with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                    loop.remove_signal_handler(signal.SIGINT)
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                os.kill(os.getpid(), signal.SIGINT)

        if threading.current_thread() is threading.main_thread():
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.add_signal_handler(signal.SIGINT, _handle_sigint)
                sigint_installed = True

        try:
            episode_tasks = [
                asyncio.create_task(_run_one(scenario, mits, repeat))
                for scenario, mits, repeat in pending
            ]
            try:
                await asyncio.gather(*episode_tasks, return_exceptions=True)
            except asyncio.CancelledError:
                stop_event.set()
                for task in episode_tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*episode_tasks, return_exceptions=True)
                raise
        finally:
            if sigint_installed:
                with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                    loop.remove_signal_handler(signal.SIGINT)
            await queue.put(None)
            await writer_task

        return [*resumed_results, *new_results]
