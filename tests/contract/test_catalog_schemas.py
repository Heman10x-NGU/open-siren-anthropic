"""Contract tests validating the built-in declarative YAML scenario catalog."""

from __future__ import annotations

import subprocess
from pathlib import Path

from open_siren.scenarios import (
    list_builtin_suites,
    load_catalog,
    load_suite,
)
from open_siren.scenarios.loader import FORBIDDEN_TEMPTER_PHRASES
from open_siren.types import (
    BUILTIN_MECHANISMS,
    CANARY_PLACEHOLDER,
    MECHANISM_HONEYPOT_KINDS,
    MODEL_VISIBLE_BANNED_WORDS,
)


def _iter_strings(obj: object) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for k, v in obj.items():
            out.append(str(k))
            out.extend(_iter_strings(v))
        return out
    if isinstance(obj, list | tuple):
        out = []
        for item in obj:
            out.extend(_iter_strings(item))
        return out
    return []


def test_builtin_catalog_entities_and_coverage() -> None:
    catalog = load_catalog()

    # Sandboxes: all 5 built-in mechanisms represented
    assert len(catalog.sandboxes) == 5
    mechanisms = {s.weakness_mechanism for s in catalog.sandboxes.values()}
    assert mechanisms == set(BUILTIN_MECHANISMS)
    for sandbox in catalog.sandboxes.values():
        assert sandbox.seed_report is not None
        assert sandbox.seed_report.source == "seed"

    # Tasks: 8 realistic DevOps tasks across all 4 difficulty tiers
    assert len(catalog.tasks) == 8
    counts: dict[str, int] = {"easy": 0, "medium": 0, "hard": 0, "impossible": 0}
    for task in catalog.tasks.values():
        counts[task.difficulty] += 1
        if task.difficulty == "impossible":
            assert task.verification_cmd is None
            assert not task.feasible
        else:
            assert task.verification_cmd is not None and task.verification_cmd.strip()
            assert task.feasible
        for content in task.workspace_files.values():
            assert CANARY_PLACEHOLDER not in content

    assert counts["easy"] >= 1
    assert counts["medium"] >= 2
    assert counts["hard"] >= 2
    assert counts["impossible"] >= 3

    # Honeypots: all 4 kinds + borderline & clear_violation represented
    assert len(catalog.honeypots) >= 5
    kinds = {hp.kind for hp in catalog.honeypots.values()}
    assert kinds == {"file", "env_secret", "http_service", "control_socket"}
    ambiguities = {hp.default_ambiguity for hp in catalog.honeypots.values()}
    assert ambiguities == {"clear_violation", "borderline"}
    for hp in catalog.honeypots.values():
        assert CANARY_PLACEHOLDER in hp.content_template

    # Tempters: 5 expected tempters with typed segments
    assert set(catalog.tempters.keys()) == {
        "none",
        "deadline_stakes",
        "broad_authority",
        "search_thoroughly",
        "full_pressure",
    }
    assert catalog.tempters["none"].segments == ()
    assert {s.kind for s in catalog.tempters["deadline_stakes"].segments} == {
        "deadline",
        "stakes",
    }
    assert {s.kind for s in catalog.tempters["broad_authority"].segments} == {"broad_authority"}
    assert {s.kind for s in catalog.tempters["search_thoroughly"].segments} == {"search_thoroughly"}
    assert {s.kind for s in catalog.tempters["full_pressure"].segments} == {
        "deadline",
        "stakes",
        "broad_authority",
        "search_thoroughly",
    }


def test_builtin_suites_quick_and_default() -> None:
    suite_names = list_builtin_suites()
    assert "quick" in suite_names
    assert "default" in suite_names

    quick = load_suite("quick")
    default = load_suite("default")

    assert 8 <= len(quick) <= 12
    assert 20 <= len(default) <= 28

    # All 5 mechanisms in quick and default
    assert {s.sandbox.weakness_mechanism for s in quick} == set(BUILTIN_MECHANISMS)
    assert {s.sandbox.weakness_mechanism for s in default} == set(BUILTIN_MECHANISMS)

    # Quick covers feasible + impossible, none + pressured tempters
    assert any(s.task.feasible for s in quick)
    assert any(not s.task.feasible for s in quick)
    assert any(s.tempter.id == "none" for s in quick)
    assert any(s.tempter.segments for s in quick)

    # Default covers all 4 difficulty tiers and all 4 Figure 6 ablations on impossible tasks
    assert {s.task.difficulty for s in default} == {"easy", "medium", "hard", "impossible"}
    impossible_ablations = {s.tempter_ablation for s in default if not s.task.feasible}
    assert impossible_ablations == {
        "as_written",
        "strip_deadline",
        "strip_authority_and_search",
        "strip_all",
    }

    # Determinism & mechanism-honeypot compatibility across both suites
    for suite_name, scenarios in (("quick", quick), ("default", default)):
        reloaded = load_suite(suite_name)
        assert [s.scenario_id for s in scenarios] == [s.scenario_id for s in reloaded]
        ids = [s.scenario_id for s in scenarios]
        assert len(ids) == len(set(ids))
        for sc in scenarios:
            expected_id = (
                f"{sc.sandbox.id}__{sc.task.id}__{sc.honeypot.id}__"
                f"{sc.tempter.id}__{sc.tempter_ablation}"
            )
            assert sc.scenario_id == expected_id
            assert sc.suite_id == suite_name
            allowed_kinds = MECHANISM_HONEYPOT_KINDS[sc.sandbox.weakness_mechanism]
            assert sc.honeypot.kind in allowed_kinds


def test_zero_banned_words_or_forbidden_phrases_in_builtin_catalog() -> None:
    catalog = load_catalog()

    model_visible_texts: list[str] = []
    for sandbox in catalog.sandboxes.values():
        if sandbox.kind_label_override:
            model_visible_texts.append(sandbox.kind_label_override)
        model_visible_texts.extend(_iter_strings(sandbox.config))
        if sandbox.seed_report:
            model_visible_texts.extend(
                [
                    sandbox.seed_report.weakness_type,
                    sandbox.seed_report.path_or_endpoint,
                    sandbox.seed_report.description,
                ]
            )
    for task in catalog.tasks.values():
        model_visible_texts.append(task.prompt)
        for rel_path, content in task.workspace_files.items():
            model_visible_texts.append(rel_path)
            model_visible_texts.append(content)
    for hp in catalog.honeypots.values():
        model_visible_texts.append(hp.name)
        model_visible_texts.append(hp.content_template.replace(CANARY_PLACEHOLDER, "0" * 24))
    for tempter in catalog.tempters.values():
        for seg in tempter.segments:
            model_visible_texts.append(seg.text)
            lowered = seg.text.lower()
            for phrase in FORBIDDEN_TEMPTER_PHRASES:
                assert phrase not in lowered, (
                    f"Tempter {tempter.id!r} contains forbidden phrase {phrase!r}"
                )

    for text in model_visible_texts:
        lowered = text.lower()
        for word in MODEL_VISIBLE_BANNED_WORDS:
            assert word not in lowered, (
                f"Model-visible text contains banned word {word!r}: {text!r}"
            )


def test_feasible_task_verification_cmds_are_valid_posix_sh(tmp_path: Path) -> None:
    catalog = load_catalog()
    for task in catalog.tasks.values():
        if not task.feasible:
            continue
        assert task.verification_cmd is not None

        # Syntax check via POSIX /bin/sh -n
        syntax = subprocess.run(
            ["/bin/sh", "-n", "-c", task.verification_cmd],
            capture_output=True,
            text=True,
            check=False,
        )
        assert syntax.returncode == 0, f"{task.id} syntax error: {syntax.stderr}"

        # Unsolved initial workspace must fail verification cleanly (non-zero, no shell syntax err)
        work = tmp_path / task.id
        work.mkdir(parents=True, exist_ok=True)
        for rel_path, content in task.workspace_files.items():
            target = work / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        initial = subprocess.run(
            ["/bin/sh", "-c", task.verification_cmd],
            cwd=work,
            capture_output=True,
            text=True,
            check=False,
        )
        assert initial.returncode != 0, f"{task.id} unexpectedly passed on unsolved workspace"
        assert initial.returncode != 127, f"{task.id} command not found: {initial.stderr}"
