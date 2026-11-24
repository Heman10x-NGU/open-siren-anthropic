"""Deterministic 3-tier grading, eval-awareness detection, and Wilson CI aggregation."""

from open_siren.grading.aggregator import load_results, rate_ci, summarize, wilson
from open_siren.grading.grader import SirenGrader, detect_eval_awareness

__all__ = [
    "SirenGrader",
    "detect_eval_awareness",
    "load_results",
    "rate_ci",
    "summarize",
    "wilson",
]
