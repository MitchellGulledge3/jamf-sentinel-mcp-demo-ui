from __future__ import annotations

"""Minimal async client for Sentinel custom MCP collections.

The terminal demo only needs three MCP operations: initialize the session,
discover tools, and call one selected tool. This module keeps that flow explicit
so Jamf developers can see the exact JSON-RPC messages and authentication
choices instead of hiding them behind a large framework.
"""

import json
import os
from dataclasses import dataclass
from itertools import count
from typing import Any

import httpx
from azure.identity.aio import ClientSecretCredential, DefaultAzureCredential

SENTINEL_RESOURCE_ID = "4500ebfb-89b6-4b14-a480-7f749797bfcd"
SENTINEL_SCOPE = f"{SENTINEL_RESOURCE_ID}/.default"
CUSTOM_COLLECTION_BASE = "https://sentinel.microsoft.com/mcp/custom"


@dataclass
class MCPTool:
    """Small local representation of a tool returned by `tools/list`."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


@dataclass
class MCPToolResult:
    """Normalized result shape returned by `tools/call`."""

    tool_name: str
    content: list[dict[str, Any]]
    is_error: bool = False

    @property
    def text(self) -> str:
        """Render text content into a display-friendly string for the terminal."""

        if not self.content:
            return ""
        parts: list[str] = []
        for item in self.content:
            if item.get("type") == "text":
                parts.append(format_tool_text(str(item.get("text", ""))))
            else:
                parts.append(json.dumps(item, indent=2))
        return "\n".join(parts)


def format_tool_text(text: str) -> str:
    """Format Kusto V2 DataSet JSON returned by Sentinel MCP into a readable table."""
    try:
        frames = json.loads(text)
    except json.JSONDecodeError:
        return text

    if not isinstance(frames, list):
        return text

    primary = next(
        (
            frame
            for frame in frames
            if isinstance(frame, dict)
            and frame.get("FrameType") == "DataTable"
            and frame.get("TableKind") == "PrimaryResult"
        ),
        None,
    )
    if not primary:
        return text

    # Kusto V2 responses carry column metadata separately from row arrays, so we
    # rebuild name/value alignment before showing the result to a human.
    columns = [col.get("ColumnName", "") for col in primary.get("Columns", [])]
    rows = primary.get("Rows", [])
    if not columns:
        return text
    if not rows:
        return "Query completed successfully, but returned no rows."

    rendered_rows = [[str(value) for value in row] for row in rows]
    widths = [
        max(len(str(columns[i])), *(len(row[i]) if i < len(row) else 0 for row in rendered_rows))
        for i in range(len(columns))
    ]

    header = " | ".join(str(columns[i]).ljust(widths[i]) for i in range(len(columns)))
    divider = "-+-".join("-" * width for width in widths)
    body = [
        " | ".join((row[i] if i < len(row) else "").ljust(widths[i]) for i in range(len(columns)))
        for row in rendered_rows
    ]
    return "\n".join([header, divider, *body])


class SentinelMCPError(RuntimeError):
    """Raised when the MCP server or Sentinel management surface rejects a call."""

    pass


class SentinelMCPClient:
    """Async Sentinel MCP client used by the local terminal demo."""

    def __init__(
        self,
        *,
        collection: str | None = None,
        server_url: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> None:
        # The demo can use either a collection name or a full server URL. The
        # collection name is easiest for developers; the URL escape hatch helps
        # if Sentinel changes endpoint routing or a proxy is introduced.
        if server_url:
            self.server_url = server_url.rstrip("/")
        elif collection:
            self.server_url = f"{CUSTOM_COLLECTION_BASE}/{collection.removeprefix('custom/')}"
        else:
            raise ValueError("Set either collection or server_url.")

        self.timeout_seconds = timeout_seconds
        self._http: httpx.AsyncClient | None = None
        self._request_ids = count(1)
        self.tools: list[MCPTool] = []

    async def connect(self) -> None:
        """Authenticate, initialize the MCP session, and cache available tools."""

        token = await self._get_token()
        self._http = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            timeout=httpx.Timeout(self.timeout_seconds),
        )

        await self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "local-sentinel-mcp-chatbot", "version": "1.0.0"},
            },
        )
        await self._send_notification("notifications/initialized", {})
        self.tools = await self.list_tools()

    async def close(self) -> None:
        """Dispose the underlying HTTP client."""

        if self._http:
            await self._http.aclose()
            self._http = None

    async def list_tools(self) -> list[MCPTool]:
        """Fetch tool metadata from the custom Sentinel MCP collection."""

        response = await self._send_request("tools/list", {})
        return [
            MCPTool(
                name=item["name"],
                description=item.get("description", ""),
                input_schema=item.get("inputSchema", {}),
            )
            for item in response.get("tools", [])
        ]

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        """Call one MCP tool by name with a JSON-object argument payload."""

        response = await self._send_request(
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )
        return MCPToolResult(
            tool_name=tool_name,
            content=response.get("content", []),
            is_error=response.get("isError", False),
        )

    async def _get_token(self) -> str:
        """Resolve credentials from environment first, then fall back to Azure CLI/browser auth."""

        tenant_id = os.getenv("AZURE_TENANT_ID")
        client_id = os.getenv("AZURE_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET")

        if tenant_id and client_id and client_secret:
            # Service-principal auth is useful for unattended demos or hosted apps.
            async with ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            ) as credential:
                return (await credential.get_token(SENTINEL_SCOPE)).token

        # DefaultAzureCredential supports Azure CLI sign-in, managed identity,
        # Visual Studio Code credentials, and other local developer flows.
        async with DefaultAzureCredential() as credential:
            return (await credential.get_token(SENTINEL_SCOPE)).token

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC request and normalize either JSON or SSE responses."""

        if not self._http:
            raise SentinelMCPError("Client is not connected.")

        request_id = next(self._request_ids)
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }

        async with self._http.stream("POST", f"{self.server_url}/", json=payload) as response:
            if response.status_code not in (200, 202):
                body = await response.aread()
                raise SentinelMCPError(f"HTTP {response.status_code}: {body.decode(errors='replace')}")

            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                # Sentinel MCP may stream JSON-RPC results over SSE, so the demo
                # supports both simple JSON and streaming responses.
                return await self._parse_sse_response(response, request_id)

            body = await response.aread()
            if not body:
                return {}
            message = json.loads(body)
            if "error" in message:
                raise SentinelMCPError(message["error"].get("message", str(message["error"])))
            return message.get("result", message)

    async def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification, which has no response ID/result."""

        if not self._http:
            raise SentinelMCPError("Client is not connected.")

        await self._http.post(
            f"{self.server_url}/",
            json={"jsonrpc": "2.0", "method": method, "params": params},
        )

    async def _parse_sse_response(self, response: httpx.Response, request_id: int) -> dict[str, Any]:
        """Collect SSE data frames until the matching JSON-RPC result appears."""

        data_lines: list[str] = []
        async for line in response.aiter_lines():
            if line.startswith("data:"):
                data_lines.append(line.removeprefix("data:").strip())
                continue

            if line == "" and data_lines:
                result = self._parse_sse_message("".join(data_lines), request_id)
                data_lines = []
                if result is not None:
                    return result

        if data_lines:
            result = self._parse_sse_message("".join(data_lines), request_id)
            if result is not None:
                return result

        raise SentinelMCPError("SSE stream ended without a JSON-RPC result.")

    @staticmethod
    def _parse_sse_message(data: str, request_id: int) -> dict[str, Any] | None:
        """Parse one SSE data payload and return only the result for our request."""

        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            return None

        if message.get("id") != request_id and "result" not in message:
            return None

        if "error" in message:
            raise SentinelMCPError(message["error"].get("message", str(message["error"])))

        return message.get("result", message)
