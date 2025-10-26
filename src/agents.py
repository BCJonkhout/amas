"""Factory helpers for assembling CrewAI agents with MCP-backed tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence

from crewai import Agent

from .documentation import DocumentationBundle, extract_agent_system_prompt, load_documentation
from .tooling import MCPToolAdapter


@dataclass(frozen=True)
class AgentBundle:
    control_tower: Agent
    issue_analysis: Agent
    overall_analysis: Agent


def build_agents(llm, server) -> AgentBundle:
    """Construct the standard AMAS agents with shared MCP tooling."""

    documentation = load_documentation()

    control_tower = _create_agent(
        llm=llm,
        server=server,
        agent_name="Control Tower Agent",
        role="Control Tower Agent",
        goal="Efficiently triage incoming alerts and dispatch deep investigations.",
        documentation=documentation,
    )

    issue_analysis = _create_agent(
        llm=llm,
        server=server,
        agent_name="Issue Analysis Agent",
        role="Issue Analysis Agent",
        goal="Perform comprehensive investigations and produce the Automated Analysis Report.",
        documentation=documentation,
    )

    overall_analysis = _create_agent(
        llm=llm,
        server=server,
        agent_name="Overall Analysis Agent",
        role="Overall Analysis Agent",
        goal="Synthesize long-term security intelligence from completed investigations.",
        documentation=documentation,
    )

    return AgentBundle(
        control_tower=control_tower,
        issue_analysis=issue_analysis,
        overall_analysis=overall_analysis,
    )


def _create_agent(llm, server, agent_name: str, role: str, goal: str, documentation: DocumentationBundle) -> Agent:
    system_prompt = extract_agent_system_prompt(agent_name, documentation)
    backstory = "\n\n".join(
        [
            system_prompt,
            "### Reference - Enterprise Asset Catalogue",
            documentation.organisation_assets,
            "### Reference - Automated Analysis Report Schema",
            documentation.desired_output,
        ]
    )
    return Agent(
        role=role,
        goal=goal,
        backstory=backstory,
        llm=llm,
        tools=list(_build_tool_adapters(server)),
        verbose=True,
    )


def _build_tool_adapters(server) -> Iterable[MCPToolAdapter]:
    tool_names = [
        "query_cmdb_assets",
        "query_iam_users",
        "query_network_vlans",
        "query_service_usage_policy",
        "query_threat_intelligence",
        "query_ueba_profiles",
        "query_edr_events",
        "query_dns_and_proxy_logs",
        "query_vulnerability_findings",
        "query_incident_response_playbooks",
    ]

    for name in tool_names:
        yield MCPToolAdapter(server, name, _get_tool_description(server, name))


def _get_tool_description(server, tool_name: str) -> str:
    registry = getattr(server, "tools", {})
    candidate = registry.get(tool_name)
    doc = getattr(candidate, "__doc__", None)
    if not doc and hasattr(candidate, "fn"):
        doc = getattr(candidate.fn, "__doc__", None)
    return doc.strip() if isinstance(doc, str) else f"MCP tool '{tool_name}'"
