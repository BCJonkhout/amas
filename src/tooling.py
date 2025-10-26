"""Adapters that let CrewAI agents call MCP tools."""

from __future__ import annotations

from typing import Any, Dict, Optional

from crewai.tools.base_tool import BaseTool
from pydantic import BaseModel, ConfigDict


class MCPToolAdapter(BaseTool):
    """Simple adapter that exposes an MCP tool as a CrewAI tool."""

    class ArgsSchema(BaseModel):
        """Validated argument contract for MCP tool calls."""

        model_config = ConfigDict(extra="allow")

        query: Optional[str] = None
        filters: Optional[Dict[str, Any]] = None

    def __init__(self, server: Any, tool_name: str, description: str) -> None:
        super().__init__(name=tool_name, description=description, args_schema=MCPToolAdapter.ArgsSchema)
        object.__setattr__(self, "_server", server)
        object.__setattr__(self, "_tool_name", tool_name)

    @property
    def server(self) -> Any:
        return getattr(self, "_server")

    @property
    def tool_name(self) -> str:
        return getattr(self, "_tool_name")

    def _run(self, query: Optional[str] = None, filters: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Any:
        """Delegate the execution to the underlying MCP tool."""

        payload: Dict[str, Any] = {}
        if query is not None:
            payload["query"] = query
        if filters is not None:
            payload["filters"] = filters
        if kwargs:
            payload.update(kwargs)

        call = self._resolve_tool_callable()
        return call(payload)

    def _resolve_tool_callable(self):
        """Best-effort resolution for the tool callable across MCP implementations."""

        if hasattr(self.server, "call_tool"):
            async def _call(arguments: Dict[str, Any]):
                return await self.server.call_tool(self.tool_name, arguments)

            return lambda args: _call(args)

        registry = getattr(self.server, "tools", None)
        if registry and self.tool_name in registry:
            candidate = registry[self.tool_name]
            if callable(candidate):
                return lambda args, fn=candidate: fn(**args)
            if hasattr(candidate, "fn"):
                return lambda args, fn=candidate.fn: fn(**args)
            if hasattr(candidate, "__call__"):
                return lambda args, fn=candidate: fn(**args)  # type: ignore[misc]

        # Fallback for potential `get_tool` helpers
        getter = getattr(self.server, "get_tool", None)
        if getter:
            candidate = getter(self.tool_name)
            if callable(candidate):
                return lambda args, fn=candidate: fn(**args)
            if hasattr(candidate, "fn"):
                return lambda args, fn=candidate.fn: fn(**args)
            if hasattr(candidate, "__call__"):
                return lambda args, fn=candidate: fn(**args)  # type: ignore[misc]

        raise AttributeError(f"MCP tool '{self.tool_name}' not found on server {self.server!r}")


MCPToolAdapter.model_rebuild(_types_namespace=globals())
