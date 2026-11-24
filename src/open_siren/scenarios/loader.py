"""Declarative YAML scenario catalog loader and validator."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from open_siren.scenarios.tempters import apply_ablation
from open_siren.types import (
    CANARY_PLACEHOLDER,
    MECHANISM_HONEYPOT_KINDS,
    MODEL_VISIBLE_BANNED_WORDS,
    AmbiguityLevel,
    HoneypotSpec,
    SandboxArchetype,
    ScenarioSpec,
    TaskSpec,
    TempterAblation,
    TempterSpec,
)

FORBIDDEN_TEMPTER_PHRASES: tuple[str, ...] = (
    "leave the sandbox",
    "outside the sandbox",
    "escape",
    "you have permission",
)

_YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})


class ScenarioValidationError(ValueError):
    """Raised when a catalog YAML file or suite violates schema or safety rules.

    The error message always names the source file path and failing field/rule.
    """

    def __init__(self, source: str | Path, field: str, message: str) -> None:
        self.source = str(source)
        self.field = field
        self.detail = message
        super().__init__(f"{self.source} [{field}]: {message}")


class _SuiteEntryRaw(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sandbox: str
    task: str
    honeypot: str
    tempters: tuple[str, ...] = Field(min_length=1)
    ablations: tuple[TempterAblation, ...] = Field(default=("as_written",), min_length=1)
    ambiguity_level: AmbiguityLevel | None = None
    tags: tuple[str, ...] = ()


class _SuiteFileRaw(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str | None = None
    description: str = ""
    entries: tuple[_SuiteEntryRaw, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class Catalog:
    """Validated collection of catalog entities and available suite names."""

    sandboxes: dict[str, SandboxArchetype]
    tasks: dict[str, TaskSpec]
    honeypots: dict[str, HoneypotSpec]
    tempters: dict[str, TempterSpec]
    suite_names: tuple[str, ...]


def _builtin_catalog_root() -> Traversable:
    return resources.files("open_siren.scenarios") / "catalog"


def _is_yaml_name(name: str) -> bool:
    return Path(name).suffix.lower() in _YAML_SUFFIXES


def _iter_yaml_nodes(directory: Traversable) -> list[Traversable]:
    if not directory.is_dir():
        return []
    nodes = [node for node in directory.iterdir() if node.is_file() and _is_yaml_name(node.name)]
    nodes.sort(key=lambda n: n.name)
    return nodes


def _read_yaml_mapping(node: Traversable) -> dict[str, Any]:
    source = str(node)
    try:
        raw_text = node.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScenarioValidationError(source, "file", f"unable to read file: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ScenarioValidationError(source, "yaml", f"invalid YAML syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioValidationError(
            source, "yaml", f"expected a YAML mapping at top level, got {type(data).__name__}"
        )
    return data


def _format_pydantic_error(exc: ValidationError) -> tuple[str, str]:
    first = exc.errors()[0]
    loc = ".".join(str(part) for part in first.get("loc", ()))
    msg = str(first.get("msg", "validation error"))
    if not loc:
        loc = "verification_cmd" if "verification_cmd" in msg else "schema"
    return loc, msg


def _parse_model[TModel: BaseModel](
    model_cls: type[TModel], data: dict[str, Any], source: str
) -> TModel:
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        field, msg = _format_pydantic_error(exc)
        raise ScenarioValidationError(source, field, msg) from exc


def _check_no_banned_words(value: str, *, source: str, field: str) -> None:
    lowered = value.lower()
    for banned in MODEL_VISIBLE_BANNED_WORDS:
        if banned in lowered:
            raise ScenarioValidationError(
                source,
                field,
                f"model-visible text contains banned word {banned!r}",
            )


def _check_config_banned_words(obj: Any, *, source: str, field: str) -> None:
    if isinstance(obj, str):
        _check_no_banned_words(obj, source=source, field=field)
    elif isinstance(obj, dict):
        for key, val in obj.items():
            key_str = str(key)
            _check_no_banned_words(key_str, source=source, field=f"{field}.{key_str}")
            _check_config_banned_words(val, source=source, field=f"{field}.{key_str}")
    elif isinstance(obj, list | tuple):
        for idx, item in enumerate(obj):
            _check_config_banned_words(item, source=source, field=f"{field}[{idx}]")


def _validate_sandbox(sandbox: SandboxArchetype, source: str) -> None:
    if sandbox.kind_label_override is not None:
        _check_no_banned_words(
            sandbox.kind_label_override,
            source=source,
            field="kind_label_override",
        )
    _check_config_banned_words(sandbox.config, source=source, field="config")
    if sandbox.seed_report is not None:
        _check_no_banned_words(
            sandbox.seed_report.weakness_type,
            source=source,
            field="seed_report.weakness_type",
        )
        _check_no_banned_words(
            sandbox.seed_report.path_or_endpoint,
            source=source,
            field="seed_report.path_or_endpoint",
        )
        _check_no_banned_words(
            sandbox.seed_report.description,
            source=source,
            field="seed_report.description",
        )


def _validate_task(task: TaskSpec, source: str) -> None:
    if task.difficulty == "impossible" and task.verification_cmd is not None:
        raise ScenarioValidationError(
            source, "verification_cmd", "impossible tasks must have verification_cmd=None"
        )
    if task.difficulty != "impossible" and (
        task.verification_cmd is None or not task.verification_cmd.strip()
    ):
        raise ScenarioValidationError(
            source,
            "verification_cmd",
            "feasible tasks must provide a non-empty verification_cmd",
        )

    _check_no_banned_words(task.prompt, source=source, field="prompt")

    for rel_path, content in task.workspace_files.items():
        field_name = f"workspace_files.{rel_path}"
        if CANARY_PLACEHOLDER in rel_path or CANARY_PLACEHOLDER in content:
            raise ScenarioValidationError(
                source,
                field_name,
                f"workspace_files must not contain {CANARY_PLACEHOLDER!r}",
            )
        _check_no_banned_words(rel_path, source=source, field=field_name)
        _check_no_banned_words(content, source=source, field=field_name)


def _validate_honeypot(honeypot: HoneypotSpec, source: str) -> None:
    if CANARY_PLACEHOLDER not in honeypot.content_template:
        raise ScenarioValidationError(
            source,
            "content_template",
            f"honeypot content_template must contain {CANARY_PLACEHOLDER!r}",
        )
    _check_no_banned_words(honeypot.name, source=source, field="name")
    rendered_preview = honeypot.content_template.replace(CANARY_PLACEHOLDER, "0" * 24)
    _check_no_banned_words(rendered_preview, source=source, field="content_template")


def _validate_tempter(tempter: TempterSpec, source: str) -> None:
    for idx, segment in enumerate(tempter.segments):
        field_name = f"segments[{idx}].text"
        _check_no_banned_words(segment.text, source=source, field=field_name)
        lowered = segment.text.lower()
        for phrase in FORBIDDEN_TEMPTER_PHRASES:
            if phrase in lowered:
                raise ScenarioValidationError(
                    source,
                    field_name,
                    f"tempter text contains forbidden phrase {phrase!r}",
                )


def _load_entities_from_dir[TEntity: (SandboxArchetype, TaskSpec, HoneypotSpec, TempterSpec)](
    root: Traversable,
    subdir: str,
    model_cls: type[TEntity],
    validator: Any,
) -> dict[str, TEntity]:
    result: dict[str, TEntity] = {}
    folder = root / subdir
    for node in _iter_yaml_nodes(folder):
        source = str(node)
        data = _read_yaml_mapping(node)
        entity = _parse_model(model_cls, data, source)
        validator(entity, source)
        entity_id = entity.id
        if entity_id in result:
            raise ScenarioValidationError(
                source, "id", f"duplicate {subdir} entity id {entity_id!r}"
            )
        result[entity_id] = entity
    return result


def _load_catalog_from_root(root: Traversable) -> Catalog:
    sandboxes = _load_entities_from_dir(root, "sandboxes", SandboxArchetype, _validate_sandbox)
    tasks = _load_entities_from_dir(root, "tasks", TaskSpec, _validate_task)
    honeypots = _load_entities_from_dir(root, "honeypots", HoneypotSpec, _validate_honeypot)
    tempters = _load_entities_from_dir(root, "tempters", TempterSpec, _validate_tempter)
    suite_nodes = _iter_yaml_nodes(root / "suites")
    suite_names = tuple(Path(node.name).stem for node in suite_nodes)
    return Catalog(
        sandboxes=sandboxes,
        tasks=tasks,
        honeypots=honeypots,
        tempters=tempters,
        suite_names=suite_names,
    )


def _merge_catalogs(base: Catalog, overlay: Catalog) -> Catalog:
    return Catalog(
        sandboxes={**base.sandboxes, **overlay.sandboxes},
        tasks={**base.tasks, **overlay.tasks},
        honeypots={**base.honeypots, **overlay.honeypots},
        tempters={**base.tempters, **overlay.tempters},
        suite_names=tuple(sorted(set(base.suite_names) | set(overlay.suite_names))),
    )


def list_builtin_suites() -> list[str]:
    """Return sorted names of built-in suites shipped in the package catalog."""
    suites_dir = _builtin_catalog_root() / "suites"
    return [Path(node.name).stem for node in _iter_yaml_nodes(suites_dir)]


def load_catalog(catalog_dir: Path | None = None) -> Catalog:
    """Load and validate all entities in the built-in catalog or ``catalog_dir``."""
    if catalog_dir is None:
        return _load_catalog_from_root(_builtin_catalog_root())
    root = Path(catalog_dir)
    if not root.is_dir():
        raise ScenarioValidationError(
            root, "catalog_dir", f"catalog directory does not exist: {root}"
        )
    return _load_catalog_from_root(root)


def _expand_suite_node(suite_node: Traversable, catalog: Catalog) -> list[ScenarioSpec]:
    source = str(suite_node)
    data = _read_yaml_mapping(suite_node)
    raw = _parse_model(_SuiteFileRaw, data, source)
    suite_id = raw.id if raw.id else Path(suite_node.name).stem

    scenarios: list[ScenarioSpec] = []
    seen_ids: set[str] = set()

    for idx, entry in enumerate(raw.entries):
        entry_prefix = f"entries[{idx}]"

        sandbox = catalog.sandboxes.get(entry.sandbox)
        if sandbox is None:
            raise ScenarioValidationError(
                source,
                f"{entry_prefix}.sandbox",
                f"unknown sandbox {entry.sandbox!r}",
            )

        task = catalog.tasks.get(entry.task)
        if task is None:
            raise ScenarioValidationError(
                source,
                f"{entry_prefix}.task",
                f"unknown task {entry.task!r}",
            )

        honeypot = catalog.honeypots.get(entry.honeypot)
        if honeypot is None:
            raise ScenarioValidationError(
                source,
                f"{entry_prefix}.honeypot",
                f"unknown honeypot {entry.honeypot!r}",
            )

        if sandbox.weakness_mechanism in MECHANISM_HONEYPOT_KINDS:
            allowed_kinds = MECHANISM_HONEYPOT_KINDS[sandbox.weakness_mechanism]
            if honeypot.kind not in allowed_kinds:
                raise ScenarioValidationError(
                    source,
                    f"{entry_prefix}.honeypot",
                    f"honeypot {honeypot.id!r} has kind {honeypot.kind!r}, which is "
                    f"incompatible with mechanism {sandbox.weakness_mechanism!r} "
                    f"(expected one of {sorted(allowed_kinds)})",
                )

        ambiguity_level = entry.ambiguity_level or honeypot.default_ambiguity

        for tempter_id in entry.tempters:
            tempter = catalog.tempters.get(tempter_id)
            if tempter is None:
                raise ScenarioValidationError(
                    source,
                    f"{entry_prefix}.tempters",
                    f"unknown tempter {tempter_id!r}",
                )

            for ablation in entry.ablations:
                ablated_tempter = apply_ablation(tempter, ablation)
                scenario_id = f"{sandbox.id}__{task.id}__{honeypot.id}__{tempter.id}__{ablation}"
                if scenario_id in seen_ids:
                    raise ScenarioValidationError(
                        source,
                        entry_prefix,
                        f"duplicate scenario_id {scenario_id!r} in suite {suite_id!r}",
                    )
                seen_ids.add(scenario_id)

                scenarios.append(
                    ScenarioSpec(
                        scenario_id=scenario_id,
                        suite_id=suite_id,
                        sandbox=sandbox,
                        task=task,
                        honeypot=honeypot,
                        tempter=ablated_tempter,
                        tempter_ablation=ablation,
                        ambiguity_level=ambiguity_level,
                        tags=entry.tags,
                    )
                )

    return scenarios


def _resolve_catalog_for_suite_file(suite_file: Path) -> Catalog:
    base = load_catalog()
    candidates: list[Path] = []
    if suite_file.parent.name == "suites":
        candidates.append(suite_file.parent.parent)
    candidates.append(suite_file.parent)

    catalog = base
    seen_roots: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen_roots:
            continue
        seen_roots.add(resolved)
        if any(
            (resolved / sub).is_dir() for sub in ("sandboxes", "tasks", "honeypots", "tempters")
        ):
            overlay = _load_catalog_from_root(resolved)
            catalog = _merge_catalogs(catalog, overlay)
    return catalog


def load_suite(name_or_path: str) -> list[ScenarioSpec]:
    """Load and validate scenarios from a built-in suite name, suite YAML file, or catalog dir."""
    builtin_suites = list_builtin_suites()
    if name_or_path in builtin_suites:
        catalog = load_catalog()
        suites_dir = _builtin_catalog_root() / "suites"
        for suffix in (".yaml", ".yml"):
            node = suites_dir / f"{name_or_path}{suffix}"
            if node.is_file():
                return _expand_suite_node(node, catalog)

    path = Path(name_or_path)
    if path.is_file():
        catalog = _resolve_catalog_for_suite_file(path)
        return _expand_suite_node(path, catalog)

    if path.is_dir():
        overlay = _load_catalog_from_root(path)
        catalog = _merge_catalogs(load_catalog(), overlay)
        suite_nodes = _iter_yaml_nodes(path / "suites")
        if not suite_nodes:
            raise ScenarioValidationError(
                path,
                "suites",
                f"catalog directory {path} contains no suite YAML files under suites/",
            )
        all_scenarios: list[ScenarioSpec] = []
        for node in suite_nodes:
            all_scenarios.extend(_expand_suite_node(node, catalog))
        return all_scenarios

    raise ScenarioValidationError(
        name_or_path,
        "suite",
        f"suite or path not found: {name_or_path!r} (built-in suites: {', '.join(builtin_suites)})",
    )


def filter_scenarios(
    scenarios: Sequence[ScenarioSpec],
    *,
    mechanisms: Collection[str] | None = None,
    difficulties: Collection[str] | None = None,
    tempters: Collection[str] | None = None,
    tags: Collection[str] | None = None,
) -> list[ScenarioSpec]:
    """Filter scenarios by mechanism, difficulty, tempter id, and/or tag intersection."""
    mech_set = set(mechanisms) if mechanisms is not None else None
    diff_set = set(difficulties) if difficulties is not None else None
    temp_set = set(tempters) if tempters is not None else None
    tag_set = set(tags) if tags is not None else None

    out: list[ScenarioSpec] = []
    for sc in scenarios:
        if mech_set is not None and sc.sandbox.weakness_mechanism not in mech_set:
            continue
        if diff_set is not None and sc.task.difficulty not in diff_set:
            continue
        if temp_set is not None and sc.tempter.id not in temp_set:
            continue
        if tag_set is not None and not (set(sc.tags) & tag_set):
            continue
        out.append(sc)
    return out
