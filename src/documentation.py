"""Utilities for loading and structuring documentation for the AMAS agents."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _candidate_data_roots() -> List[Path]:
    roots: List[Path] = []
    env_override = os.environ.get("AMAS_DATA_DIR")
    if env_override:
        roots.append(Path(env_override).expanduser())
    roots.append(PROJECT_ROOT / "data")
    return roots


def _resolve_documentation_dir() -> Path:
    attempts: List[Path] = []
    for root in _candidate_data_roots():
        doc_dir = (root / "documentation").resolve()
        attempts.append(doc_dir)
        if doc_dir.is_dir():
            return doc_dir
    attempted = ", ".join(str(path) for path in attempts)
    raise FileNotFoundError(f"Documentation directory not found. Checked: {attempted}")


DOCUMENTATION_DIR = _resolve_documentation_dir()


@dataclass(frozen=True)
class DocumentationBundle:
    """Container for all documentation snippets we expose to the agents."""

    system_prompt: str
    organisation_assets: str
    desired_output: str

    def as_dict(self) -> Dict[str, str]:
        """Return the bundle as a plain dictionary."""
        return {
            "system_prompt": self.system_prompt,
            "organisation_assets": self.organisation_assets,
            "desired_output": self.desired_output,
        }


def _read_text(file_name: str) -> str:
    path = DOCUMENTATION_DIR / file_name
    if not path.is_file():
        raise FileNotFoundError(f"Documentation file not found: {path}")
    return path.read_text(encoding="utf-8")


def load_documentation() -> DocumentationBundle:
    """Load the core documentation artefacts from disk."""

    return DocumentationBundle(
        system_prompt=_read_text("SYSTEM_PROMPT.md"),
        organisation_assets=_read_text("ORGANISATION_ASSETS.md"),
        desired_output=_read_text("DESIRED_OUTPUT.md"),
    )


def extract_agent_system_prompt(agent_name: str, documentation: DocumentationBundle) -> str:
    """Pull the section from SYSTEM_PROMPT.md that targets the requested agent."""

    section_title = {
        "Control Tower Agent": "1. System Prompt: Control Tower Agent",
        "Issue Analysis Agent": "2. System Prompt: Issue Analysis Agent",
        "Overall Analysis Agent": "3. System Prompt: Overall Analysis Agent",
    }.get(agent_name)

    if not section_title:
        raise ValueError(f"Unknown agent name: {agent_name}")

    return _extract_markdown_section(documentation.system_prompt, section_title)


def _extract_markdown_section(markdown: str, title: str) -> str:
    heading = f"### {title}"
    lines = markdown.splitlines()
    start_index: Optional[int] = None

    for index, line in enumerate(lines):
        if line.strip() == heading:
            start_index = index
            break

    if start_index is None:
        return markdown.strip()

    end_index = len(lines)
    for index in range(start_index + 1, len(lines)):
        if lines[index].startswith("### "):
            end_index = index
            break

    return "\n".join(lines[start_index:end_index]).strip()


def build_agent_prompt(agent_name: str, documentation: DocumentationBundle) -> str:
    """Craft a consolidated prompt that keeps documentation close to each agent.

    The MCP tools let the LLM fetch targeted data at run-time, but we also want
    the planning and reasoning layers to have instant access to the operating
    doctrine defined in the Markdown documentation. By embedding the relevant
    sections directly in the agent prompt we guarantee that every LLM call
    starts with full situational awareness.
    """

    core = [
        f"### Authoritative Documentation Snapshot for {agent_name}",
        documentation.system_prompt,
        "\n\n### Enterprise Asset & Data Source Catalogue",
        documentation.organisation_assets,
        "\n\n### Automated Analysis Report Schema",
        documentation.desired_output,
    ]
    return "\n".join(core)
