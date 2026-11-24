"""Declarative scenario catalog, loader, validation, tempter ablation, and search."""

from __future__ import annotations

from open_siren.scenarios.evolve import (
    CandidateTempter,
    EvolutionReport,
    TempterSearchPipeline,
    deduplicate_tempters,
    ngram_jaccard,
    validate_candidate_tempter,
)
from open_siren.scenarios.loader import (
    Catalog,
    ScenarioValidationError,
    filter_scenarios,
    list_builtin_suites,
    load_catalog,
    load_suite,
)
from open_siren.scenarios.tempters import apply_ablation

__all__ = [
    "CandidateTempter",
    "Catalog",
    "EvolutionReport",
    "ScenarioValidationError",
    "TempterSearchPipeline",
    "apply_ablation",
    "deduplicate_tempters",
    "filter_scenarios",
    "list_builtin_suites",
    "load_catalog",
    "load_suite",
    "ngram_jaccard",
    "validate_candidate_tempter",
]
