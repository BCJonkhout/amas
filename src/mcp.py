"""Model Context Protocol server exposing enterprise security data sources."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - guard for missing dependency
    raise RuntimeError(
        "The `mcp` package is required to run the security data server. "
        "Install it via `pip install mcp`."
    ) from exc

from .security_data import DATASET_CATALOGUE, SecurityDataRepository


def create_security_data_server(repository: Optional[SecurityDataRepository] = None) -> FastMCP:
    """Instantiate a FastMCP server with one tool per enterprise dataset."""

    repo = repository or SecurityDataRepository()
    server = FastMCP("amas-security-data")

    @server.tool()
    def query_cmdb_assets(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve CMDB assets. Use `query` for substring search or `filters` with dot-notation keys."""

        return repo.query("cmdb", query=query, filters=filters)

    @server.tool()
    def query_iam_users(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve IAM and HR identity records."""

        return repo.query("iam", query=query, filters=filters)

    @server.tool()
    def query_network_vlans(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve network VLAN architecture documentation."""

        return repo.query("network_vlans", query=query, filters=filters)

    @server.tool()
    def query_service_usage_policy(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve approved service and port usage policies."""

        return repo.query("service_policy", query=query, filters=filters)

    @server.tool()
    def query_threat_intelligence(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve threat intelligence indicators."""

        return repo.query("threat_intel", query=query, filters=filters)

    @server.tool()
    def query_ueba_profiles(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve UEBA baseline profiles."""

        return repo.query("ueba", query=query, filters=filters)

    @server.tool()
    def query_edr_events(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve endpoint detection and response telemetry."""

        return repo.query("edr_events", query=query, filters=filters)

    @server.tool()
    def query_dns_and_proxy_logs(
        query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve DNS and web proxy telemetry. Filter with `log_type` to select DNS or proxy entries."""

        return repo.query("dns_proxy", query=query, filters=filters)

    @server.tool()
    def query_vulnerability_findings(query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve vulnerability scan findings."""

        return repo.query("vuln_scans", query=query, filters=filters)

    @server.tool()
    def query_incident_response_playbooks(
        query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve incident response playbooks."""

        return repo.query("playbooks", query=query, filters=filters)

    datasets_meta = {config.dataset_id: config.description for config in DATASET_CATALOGUE}
    if hasattr(server, "metadata") and isinstance(server.metadata, dict):
        server.metadata["datasets"] = datasets_meta
    else:  # pragma: no cover - compatibility shim
        setattr(server, "metadata", {"datasets": datasets_meta})
    return server
