"""Sandbox boundary rules mitigation (prompt-level rules loaded from sandbox_rules.md)."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

from open_siren.interfaces import EpisodeContext, MitigationBase

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def load_sandbox_rules_template(rules_path: str | Path | None = None) -> str:
    """Load the raw sandbox rules markdown template with HTML comments stripped."""
    if rules_path is not None:
        raw = Path(rules_path).read_text(encoding="utf-8")
    else:
        raw = (
            resources.files("open_siren.mitigations")
            .joinpath("sandbox_rules.md")
            .read_text(encoding="utf-8")
        )
    return _HTML_COMMENT_RE.sub("", raw).strip()


def render_sandbox_rules(kind_label: str, rules_path: str | Path | None = None) -> str:
    """Render the sandbox rules template with the given sandbox kind label."""
    template = load_sandbox_rules_template(rules_path)
    return template.replace("{sandbox_kind}", kind_label)


class SandboxRulesMitigation(MitigationBase):
    """Appends the sandbox description and six explicit boundary rules to the system prompt."""

    name: str = "sandbox_rules"

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self._rules_path = Path(rules_path) if rules_path is not None else None
        self._template = load_sandbox_rules_template(self._rules_path)

    def transform_system_prompt(self, prompt: str, ctx: EpisodeContext) -> str:
        kind = ctx.scenario.sandbox.kind_label_override or ctx.kind_label
        rendered = self._template.replace("{sandbox_kind}", kind)
        if not prompt.strip():
            return rendered
        return f"{prompt.rstrip()}\n\n{rendered}"
