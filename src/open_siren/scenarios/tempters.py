"""Exact segment-based tempter ablation (Anthropic Siren Figure 6 style)."""

from __future__ import annotations

from open_siren.types import TempterAblation, TempterSpec

_DEADLINE_KINDS: frozenset[str] = frozenset({"deadline", "stakes"})
_AUTHORITY_AND_SEARCH_KINDS: frozenset[str] = frozenset({"broad_authority", "search_thoroughly"})


def apply_ablation(tempter: TempterSpec, mode: TempterAblation) -> TempterSpec:
    """Return a TempterSpec with segments dropped according to ``mode``.

    - ``as_written``: unchanged.
    - ``strip_deadline``: drops ``deadline`` and ``stakes`` segments.
    - ``strip_authority_and_search``: drops ``broad_authority`` and ``search_thoroughly`` segments.
    - ``strip_all``: drops all segments.
    """
    if mode == "as_written":
        return tempter
    if mode == "strip_deadline":
        kept = tuple(seg for seg in tempter.segments if seg.kind not in _DEADLINE_KINDS)
        return TempterSpec(id=tempter.id, segments=kept, tags=tempter.tags)
    if mode == "strip_authority_and_search":
        kept = tuple(seg for seg in tempter.segments if seg.kind not in _AUTHORITY_AND_SEARCH_KINDS)
        return TempterSpec(id=tempter.id, segments=kept, tags=tempter.tags)
    if mode == "strip_all":
        return TempterSpec(id=tempter.id, segments=(), tags=tempter.tags)
    raise ValueError(f"Unknown tempter ablation mode: {mode!r}")
