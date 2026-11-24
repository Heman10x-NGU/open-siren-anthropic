"""Orphan container, volume, and temporary directory cleanup for Open Siren."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from open_siren.sandboxes._common import EPISODE_BASE_DIR


def _is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _run_docker_sync(
    args: list[str], timeout_s: float = 10.0
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _reap_docker_containers(dry_run: bool) -> list[str]:
    res = _run_docker_sync(
        [
            "ps",
            "-a",
            "--filter",
            "label=open-siren.managed=true",
            "--format",
            '{{.ID}}\t{{.Names}}\t{{.Label "open-siren.owner_pid"}}',
        ]
    )
    if res is None or res.returncode != 0:
        return []

    reaped: list[str] = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        cid = parts[0].strip()
        name = parts[1].strip()
        pid_raw = parts[2].strip() if len(parts) >= 3 else ""
        try:
            owner_pid = int(pid_raw)
        except ValueError:
            owner_pid = -1

        if not _is_pid_alive(owner_pid):
            reaped.append(f"container:{name} ({cid})")
            if not dry_run:
                _run_docker_sync(["rm", "-f", cid], timeout_s=15.0)
    return reaped


def _reap_docker_volumes(dry_run: bool) -> list[str]:
    ls_res = _run_docker_sync(
        [
            "volume",
            "ls",
            "--filter",
            "label=open-siren.managed=true",
            "--format",
            "{{.Name}}",
        ]
    )
    if ls_res is None or ls_res.returncode != 0:
        return []

    vol_names = [v.strip() for v in ls_res.stdout.splitlines() if v.strip()]
    if not vol_names:
        return []

    inspect_res = _run_docker_sync(
        [
            "volume",
            "inspect",
            "--format",
            '{{.Name}}\t{{index .Labels "open-siren.owner_pid"}}',
            *vol_names,
        ]
    )
    if inspect_res is None or inspect_res.returncode != 0:
        return []

    reaped: list[str] = []
    for line in inspect_res.stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        vol_name = parts[0].strip()
        pid_raw = parts[1].strip() if len(parts) >= 2 else ""
        try:
            owner_pid = int(pid_raw)
        except ValueError:
            owner_pid = -1

        if not _is_pid_alive(owner_pid):
            reaped.append(f"volume:{vol_name}")
            if not dry_run:
                _run_docker_sync(["volume", "rm", "-f", vol_name], timeout_s=15.0)
    return reaped


def _reap_stale_dirs(dry_run: bool, max_age_seconds: int, base_dir: Path) -> list[str]:
    if not base_dir.exists():
        return []

    now = time.time()
    reaped: list[str] = []
    try:
        entries = sorted(base_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return []

    for entry in entries:
        try:
            st = entry.lstat()
        except OSError:
            continue
        age = now - st.st_mtime
        if age >= max_age_seconds:
            reaped.append(f"dir:{entry}")
            if not dry_run:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
    return reaped


def reap(
    dry_run: bool = False,
    max_age_seconds: int = 3600,
    *,
    base_dir: Path = EPISODE_BASE_DIR,
) -> list[str]:
    """Reap orphaned Open Siren Docker containers/volumes and stale `/tmp/osr/*` dirs.

    When ``dry_run=True``, returns the resource identifiers that would be removed
    without modifying anything. Gracefully skips Docker if the daemon is unavailable.
    """
    reaped: list[str] = []
    reaped.extend(_reap_docker_containers(dry_run=dry_run))
    reaped.extend(_reap_docker_volumes(dry_run=dry_run))
    reaped.extend(
        _reap_stale_dirs(
            dry_run=dry_run,
            max_age_seconds=max_age_seconds,
            base_dir=base_dir,
        )
    )
    return reaped
