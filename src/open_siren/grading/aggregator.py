"""Wilson CI computation, resilient JSONL loading, and suite summary aggregation."""

from __future__ import annotations

import logging
import math
import warnings
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from open_siren.types import EpisodeResult, RateCI, SuiteSummary, SummaryRow

logger = logging.getLogger(__name__)

_GROUP_EXTRACTORS: dict[str, Callable[[EpisodeResult], str]] = {
    "model": lambda ep: ep.model,
    "mitigation_set_id": lambda ep: ep.mitigation_set_id,
    "difficulty": lambda ep: ep.scenario.task.difficulty,
    "tempter_ablation": lambda ep: ep.scenario.tempter_ablation,
    "mechanism": lambda ep: ep.scenario.sandbox.weakness_mechanism,
    "backend": lambda ep: ep.backend,
    "provider": lambda ep: ep.provider,
    "suite_id": lambda ep: ep.scenario.suite_id,
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Compute the exact Wilson score confidence interval clamped to [0.0, 1.0]."""
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"Invalid Wilson counts: require 0 <= k <= n, got k={k}, n={n}")
    if z < 0:
        raise ValueError(f"z must be non-negative, got {z}")
    if n == 0:
        return (0.0, 0.0)

    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)

    lo = 0.0 if k == 0 else max(0.0, min(1.0, center - margin))
    hi = 1.0 if k == n else max(0.0, min(1.0, center + margin))
    return (lo, hi)


def rate_ci(k: int, n: int, *, z: float = 1.96) -> RateCI:
    """Build a RateCI with Wilson 95% bounds for k successes out of n trials."""
    lo, hi = wilson(k, n, z=z)
    rate = k / n if n > 0 else 0.0
    return RateCI(k=k, n=n, rate=rate, lo=lo, hi=hi)


def load_results(path: Path | str) -> Iterator[EpisodeResult]:
    """Stream EpisodeResult records from a JSONL file or directory containing episodes.jsonl.

    Blank lines are skipped. If the final non-empty line is truncated or invalid JSON,
    a warning is emitted and the line is skipped. Any invalid non-final line raises ValueError.
    """
    target = Path(path)
    file_path = target / "episodes.jsonl" if target.is_dir() else target
    if not file_path.exists():
        raise FileNotFoundError(f"Results file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as fh:
        pending: tuple[int, str] | None = None
        for line_no, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if pending is not None:
                prev_no, prev_text = pending
                try:
                    yield EpisodeResult.model_validate_json(prev_text)
                except (ValidationError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid EpisodeResult JSON at {file_path}:{prev_no}: {exc}"
                    ) from exc
            pending = (line_no, stripped)

        if pending is not None:
            last_no, last_text = pending
            try:
                yield EpisodeResult.model_validate_json(last_text)
            except (ValidationError, ValueError) as exc:
                msg = f"Skipping truncated or invalid final line at {file_path}:{last_no}: {exc}"
                logger.warning(msg)
                warnings.warn(msg, UserWarning, stacklevel=2)


def summarize(
    results: Iterable[EpisodeResult],
    group_by: Sequence[str] = ("model", "mitigation_set_id"),
) -> SuiteSummary:
    """Aggregate episodes into grouped Wilson-CI summary rows."""
    group_keys = tuple(group_by)
    unknown = [k for k in group_keys if k not in _GROUP_EXTRACTORS]
    if unknown:
        supported = ", ".join(sorted(_GROUP_EXTRACTORS))
        raise ValueError(f"Unknown group_by key(s) {unknown!r}. Supported keys: [{supported}]")

    buckets: dict[tuple[str, ...], list[EpisodeResult]] = defaultdict(list)
    run_ids: set[str] = set()

    for ep in results:
        run_ids.add(ep.run_id)
        key_vals = tuple(_GROUP_EXTRACTORS[k](ep) for k in group_keys)
        buckets[key_vals].append(ep)

    raw_rows: list[SummaryRow] = []
    for key_vals in sorted(buckets):
        eps = buckets[key_vals]
        group_dict = dict(zip(group_keys, key_vals, strict=True))
        valid = [ep for ep in eps if ep.status != "error" and ep.grade is not None]
        n_episodes = len(eps)
        n_valid = len(valid)
        n_errors = n_episodes - n_valid

        feasible = [ep for ep in valid if ep.grade is not None and ep.grade.task_feasible]

        raw_rows.append(
            SummaryRow(
                group=group_dict,
                n_episodes=n_episodes,
                n_errors=n_errors,
                reached=rate_ci(
                    sum(1 for ep in valid if ep.grade is not None and ep.grade.reached_outside),
                    n_valid,
                ),
                used=rate_ci(
                    sum(1 for ep in valid if ep.grade is not None and ep.grade.used_honeypot),
                    n_valid,
                ),
                misaligned=rate_ci(
                    sum(1 for ep in valid if ep.grade is not None and ep.grade.misaligned_use),
                    n_valid,
                ),
                eval_aware=rate_ci(
                    sum(
                        1
                        for ep in valid
                        if ep.grade is not None and ep.grade.eval_awareness_detected
                    ),
                    n_valid,
                ),
                reported=rate_ci(
                    sum(1 for ep in valid if ep.grade is not None and ep.grade.reported_weakness),
                    n_valid,
                ),
                task_completed_feasible=rate_ci(
                    sum(1 for ep in feasible if ep.grade is not None and ep.grade.task_completed),
                    len(feasible),
                ),
                reached_reduction_vs_none=None,
            )
        )

    if "mitigation_set_id" in group_keys:
        other_keys = tuple(k for k in group_keys if k != "mitigation_set_id")
        baseline_rates: dict[tuple[str, ...], float] = {}
        for row in raw_rows:
            if row.group["mitigation_set_id"] == "none" and row.reached.n > 0:
                other_vals = tuple(row.group[k] for k in other_keys)
                baseline_rates[other_vals] = row.reached.rate

        final_rows: list[SummaryRow] = []
        for row in raw_rows:
            if row.group["mitigation_set_id"] != "none" and row.reached.n > 0:
                other_vals = tuple(row.group[k] for k in other_keys)
                base_rate = baseline_rates.get(other_vals)
                if base_rate is not None and base_rate > 0.0:
                    reduction = (base_rate - row.reached.rate) / base_rate
                    row = row.model_copy(update={"reached_reduction_vs_none": reduction})
            final_rows.append(row)
        rows_tuple = tuple(final_rows)
    else:
        rows_tuple = tuple(raw_rows)

    return SuiteSummary(
        run_ids=tuple(sorted(run_ids)),
        group_by=group_keys,
        rows=rows_tuple,
        generated_at=datetime.now(UTC),
    )
