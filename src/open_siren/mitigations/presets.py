"""Canonical mitigation ordering, ID formatting, and CLI preset parsing."""

from __future__ import annotations

from collections.abc import Iterable

CANONICAL_ORDER: tuple[str, ...] = (
    "sandbox_rules",
    "report_tools",
    "view_reports",
    "auto_gate",
)

_CANONICAL_INDEX: dict[str, int] = {name: idx for idx, name in enumerate(CANONICAL_ORDER)}


def canonicalize_mitigations(names: Iterable[str]) -> tuple[str, ...]:
    """Expand aliases ('all', 'none'), imply report_tools for view_reports, dedupe, and sort."""
    expanded: set[str] = set()
    for raw in names:
        name = raw.strip()
        if not name or name == "none":
            continue
        if name == "all":
            expanded.update(CANONICAL_ORDER)
            continue
        expanded.add(name)

    if "view_reports" in expanded:
        expanded.add("report_tools")

    builtins = [n for n in CANONICAL_ORDER if n in expanded]
    custom = sorted(n for n in expanded if n not in _CANONICAL_INDEX)
    return tuple(builtins + custom)


def mitigation_set_id(names: Iterable[str]) -> str:
    """Return canonical '+'-joined mitigation identifier, or 'none' when empty."""
    canonical = canonicalize_mitigations(names)
    return "+".join(canonical) if canonical else "none"


def parse_mitigation_sets(spec: str) -> list[tuple[str, ...]]:
    """Parse a comma-separated list of '+'-joined mitigation sets.

    Example:
        "none,sandbox_rules,view_reports,sandbox_rules+auto_gate,all"
    """
    stripped = spec.strip()
    if not stripped:
        return [()]

    sets: list[tuple[str, ...]] = []
    for raw_set in stripped.split(","):
        part = raw_set.strip()
        if not part:
            continue
        tokens = [tok.strip() for tok in part.split("+") if tok.strip()]
        sets.append(canonicalize_mitigations(tokens))
    return sets if sets else [()]
