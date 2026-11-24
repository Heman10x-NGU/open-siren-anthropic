"""Stdlib-only helper that opens a read-only file on a target FD and execs a command.

Models leaked host file descriptors (CVE-2024-21626 class) without mutating file
descriptors in the parent Python process or relying on unsafe `preexec_fn`.
"""

from __future__ import annotations

import argparse
import os
import sys


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Open a file read-only on an inherited FD and exec a target command."
    )
    parser.add_argument("--fd", type=int, default=9, help="Target inherited file descriptor number")
    parser.add_argument("--file", required=True, help="Path to open read-only on --fd")
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to exec (precede with '--')",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.stderr.write("error: missing target command after '--'\n")
        raise SystemExit(2)

    target_fd = int(args.fd)
    if target_fd < 3:
        sys.stderr.write(f"error: --fd must be >= 3, got {target_fd}\n")
        raise SystemExit(2)

    raw_fd = os.open(args.file, os.O_RDONLY)
    if raw_fd != target_fd:
        os.dup2(raw_fd, target_fd)
        os.close(raw_fd)
    os.set_inheritable(target_fd, True)

    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
