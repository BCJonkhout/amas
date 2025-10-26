"""High-level orchestration for running AMAS investigations."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from crewai import Crew, Process, Task

from .agents import AgentBundle, build_agents
from .documentation import load_documentation
from .mcp import create_security_data_server
from .security_data import SecurityDataRepository


@dataclass(frozen=True)
class WorkflowContext:
    crew: Crew
    agents: AgentBundle

class InvestigationError(RuntimeError):
    """Raised when an investigation run fails while capturing logs."""

    def __init__(self, message: str, *, logs: Optional[str] = None):
        super().__init__(message)
        self.logs = logs


def build_workflow(llm, repository: Optional[SecurityDataRepository] = None):
    """Instantiate the MCP server, agents, and crew for investigations."""

    repo = repository or SecurityDataRepository()
    server = create_security_data_server(repo)
    agents = build_agents(llm=llm, server=server)
    documentation = load_documentation()

    control_tower_task = Task(
        description=(
            "### Incoming Security Alert\n"
            "{alert_json}\n\n"
            "1. Query the CMDB with the MCP tools (e.g., `query_cmdb_assets`) to determine asset criticality.\n"
            "2. Analyse associated users, network zones, and policy context using the available MCP tools.\n"
            "3. Produce a structured investigation plan for the Issue Analysis Agent.\n"
            "Leverage the embedded documentation for guidance:\n"
            f"{documentation.system_prompt}\n"
        ),
        expected_output="A JSON investigation plan describing required data sources, rationale, and next steps.",
        agent=agents.control_tower,
    )

    issue_analysis_task = Task(
        description=(
            "Execute the investigation plan provided by the Control Tower Agent. "
            "Use the MCP tools to gather evidence across CMDB, IAM, UEBA, logs, threat intelligence, "
            "and policy datasets. Your final response must strictly follow the Automated Analysis Report schema:\n"
            f"{documentation.desired_output}\n"
        ),
        expected_output="A single JSON object that conforms to the Automated Analysis Report schema.",
        agent=agents.issue_analysis,
        context=[control_tower_task],
    )

    crew = Crew(
        agents=[agents.control_tower, agents.issue_analysis],
        tasks=[control_tower_task, issue_analysis_task],
        process=Process.sequential,
        verbose=True,
    )

    return WorkflowContext(crew=crew, agents=agents)


def run_alert_investigation(
    alert_payload: Dict[str, Any],
    llm,
    repository: Optional[SecurityDataRepository] = None,
    *,
    capture_logs: bool = False,
) -> Union[Any, Tuple[Any, str]]:
    """Execute the end-to-end investigation workflow for a single alert.

    Args:
        alert_payload: The raw alert document to investigate.
        llm: The language model instance used by the Crew.
        repository: Optional shared security data repository.
        capture_logs: When true, returns a tuple of (result, verbose_logs)
            by capturing stdout emitted by CrewAI's verbose mode.

    Returns:
        The final crew output if ``capture_logs`` is False, otherwise a tuple
        containing the output and captured logs.
    """

    workflow = build_workflow(llm=llm, repository=repository)
    inputs = {"alert_json": json.dumps(alert_payload)}

    if not capture_logs:
        return workflow.crew.kickoff(inputs=inputs)

    buffer = io.StringIO()
    try:
        with redirect_stdout(buffer):
            result = workflow.crew.kickoff(inputs=inputs)
    except Exception as exc:
        logs = buffer.getvalue()
        raise InvestigationError(f"Crew execution failed: {exc}", logs=logs) from exc
    return result, buffer.getvalue()
