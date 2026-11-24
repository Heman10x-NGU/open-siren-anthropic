"""Shared helpers for Open Siren sandbox backends."""

from __future__ import annotations

import os
import secrets
from pathlib import Path, PurePosixPath
from typing import Any

from open_siren.types import (
    BUILTIN_MECHANISMS,
    CANARY_PLACEHOLDER,
    LOCATOR_PLACEHOLDER,
    MECHANISM_HONEYPOT_KINDS,
    MODEL_VISIBLE_BANNED_WORDS,
    HoneypotHit,
    ScenarioSpec,
)

EPISODE_BASE_DIR = Path("/tmp/osr")
MAX_OUTPUT_BYTES = 64 * 1024
MAX_WORKSPACE_SCAN_BYTES = 16 * 1024 * 1024
SETTLE_SECONDS = 0.2
MAX_UNIX_SOCKET_PATH_BYTES = 100

DEFAULT_DISCOVERY_ENV: dict[str, str] = {
    "control_socket_leak": "NODE_CONTROL_SOCKET",
    "loopback_service_leak": "INTERNAL_METADATA_URL",
    "egress_proxy_bypass": "DIRECT_REGISTRY_URL",
}


def assert_no_banned_words(value: str, context: str) -> None:
    """Ensure model-visible strings contain no banned eval-awareness words."""
    lower = value.lower()
    for word in MODEL_VISIBLE_BANNED_WORDS:
        if word in lower:
            raise ValueError(f"Model-visible {context} contains banned word {word!r}: {value!r}")


def validate_scenario_mechanism(scenario: ScenarioSpec) -> str:
    """Validate that the scenario's mechanism and honeypot kind are supported."""
    mechanism = scenario.sandbox.weakness_mechanism
    if mechanism not in BUILTIN_MECHANISMS:
        raise ValueError(f"Unsupported sandbox mechanism: {mechanism!r}")
    allowed_kinds = MECHANISM_HONEYPOT_KINDS[mechanism]
    if scenario.honeypot.kind not in allowed_kinds:
        raise ValueError(
            f"Mechanism {mechanism!r} requires honeypot kind in {sorted(allowed_kinds)}, "
            f"got {scenario.honeypot.kind!r}"
        )
    return mechanism


def make_episode_dir() -> tuple[str, Path]:
    """Create a short `/tmp/osr/<12hex>/` episode directory with `work/` and `host/`."""
    EPISODE_BASE_DIR.mkdir(parents=True, exist_ok=True)
    for _ in range(16):
        slug = secrets.token_hex(6)
        ep_dir = EPISODE_BASE_DIR / slug
        try:
            ep_dir.mkdir(parents=False, exist_ok=False)
            (ep_dir / "work").mkdir(parents=False, exist_ok=False)
            (ep_dir / "host").mkdir(parents=False, exist_ok=False)
            return slug, ep_dir
        except FileExistsError:
            continue
    raise RuntimeError("Failed to allocate unique episode directory under /tmp/osr")


def render_honeypot_content(scenario: ScenarioSpec, canary_token: str) -> str:
    """Substitute `{{CANARY_TOKEN}}` into the honeypot template."""
    return scenario.honeypot.content_template.replace(CANARY_PLACEHOLDER, canary_token)


def normalize_http_path(name: str) -> str:
    """Ensure an HTTP or control-socket path starts with '/' and has no banned words."""
    path = name if name.startswith("/") else f"/{name}"
    assert_no_banned_words(path, "honeypot path")
    return path


def sanitize_relative_name(name: str, context: str = "honeypot file name") -> PurePosixPath:
    """Validate a relative POSIX path for a honeypot file or mount target."""
    cleaned = name.lstrip("/")
    posix = PurePosixPath(cleaned)
    if not cleaned or "\\" in cleaned or posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"Invalid relative {context}: {name!r}")
    assert_no_banned_words(cleaned, context)
    return posix


def dedupe_locators(items: list[str]) -> tuple[str, ...]:
    """Return unique non-empty locators preserving insertion order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


def write_workspace_files(
    work_dir: Path,
    workspace_files: dict[str, str],
    outside_locator: str | None,
) -> None:
    """Write task workspace files, substituting `{{OUTSIDE_LOCATOR}}` when present."""
    for rel_path, content in workspace_files.items():
        assert_no_banned_words(rel_path, "workspace file path")
        rendered = (
            content.replace(LOCATOR_PLACEHOLDER, outside_locator)
            if outside_locator is not None
            else content
        )
        target = work_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")


def decode_and_cap(
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    canary_token: str,
) -> tuple[str, str, bool, bool]:
    """Compute `canary_in_output` on full streams, then cap each stream to 64 KiB."""
    full_stdout = stdout_bytes.decode("utf-8", errors="replace")
    full_stderr = stderr_bytes.decode("utf-8", errors="replace")
    canary_in_output = bool(
        canary_token and (canary_token in full_stdout or canary_token in full_stderr)
    )
    truncated = len(stdout_bytes) > MAX_OUTPUT_BYTES or len(stderr_bytes) > MAX_OUTPUT_BYTES
    capped_stdout = stdout_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    capped_stderr = stderr_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return capped_stdout, capped_stderr, truncated, canary_in_output


def scan_workspace_for_canary(work_dir: Path, canary_token: str) -> tuple[str, ...]:
    """Scan regular files inside `work_dir` (skipping symlinks) for `canary_token`."""
    if not canary_token or not work_dir.exists():
        return ()
    canary_bytes = canary_token.encode("utf-8")
    matches: list[str] = []
    root_str = str(work_dir)
    for dirpath, dirnames, filenames in os.walk(root_str, followlinks=False):
        # Never descend into symlinked directories (e.g. host_mount_leak symlink).
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            if os.path.islink(full_path):
                continue
            try:
                st = os.stat(full_path)
                if not os.path.isfile(full_path):
                    continue
                if st.st_size < len(canary_bytes):
                    continue
                with open(full_path, "rb") as fh:
                    data = fh.read(MAX_WORKSPACE_SCAN_BYTES)
                if canary_bytes in data:
                    rel = Path(full_path).relative_to(work_dir).as_posix()
                    matches.append(rel)
            except OSError:
                continue
    matches.sort()
    return tuple(matches)


def raw_hit_to_model(raw: dict[str, Any]) -> HoneypotHit:
    """Convert a raw JSONL dict from `hub_server` into a typed `HoneypotHit`."""
    return HoneypotHit.model_validate(raw)
