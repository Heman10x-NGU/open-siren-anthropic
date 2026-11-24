"""Pytest fixtures for Docker sandbox tests; auto-skips when Docker daemon is unavailable."""

from __future__ import annotations

import asyncio

import pytest

from open_siren.sandboxes.docker_sandbox import DockerSandboxBackend


def _docker_available() -> tuple[bool, str]:
    backend = DockerSandboxBackend()
    return asyncio.run(backend.check_available())


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    docker_items = [item for item in items if "docker" in item.keywords]
    if not docker_items:
        return
    ok, detail = _docker_available()
    if not ok:
        skip_marker = pytest.mark.skip(reason=f"Docker daemon unavailable: {detail}")
        for item in docker_items:
            item.add_marker(skip_marker)


@pytest.fixture
def docker_backend() -> DockerSandboxBackend:
    return DockerSandboxBackend()
