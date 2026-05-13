from __future__ import annotations

"""Mock MCP client used when the terminal demo runs without Azure connectivity.

The mock intentionally mirrors the small interface exposed by `SentinelMCPClient`
so the rest of the terminal app can switch between `MCP_DEMO_MODE=mock` and
`MCP_DEMO_MODE=real` without branching throughout the codebase.
"""

import json
from typing import Any

from .client import MCPTool, MCPToolResult


class MockSentinelMCPClient:
    """Return deterministic MCP-like results for offline presenter practice."""

    def __init__(self) -> None:
        self.tools = [
            MCPTool(
                name="Jamf_Alert_Posture_Summary",
                description="Summarize Jamf Protect alert posture across event types, severities, and hosts.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_Prevented_Execution_Hunt",
                description="Hunt prevented process executions with process, signer, hash, and command-line context.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_Unsigned_Binary_Activity",
                description="Find unsigned binary activity grouped by path with hit counts and distinct hosts.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_USB_Storage_Activity",
                description="Summarize USB mount and block events by hostname, serial, and severity.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_Mac_Endpoint_Risk_Profile",
                description="Compute per-Mac risk scores from severity, prevention, unsigned binaries, and Gatekeeper events.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_Gatekeeper_MRT_Watch",
                description="Monitor macOS-native protection activity: Gatekeeper, MRT, ProcessDenied, ProcessPrevented.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
        ]

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def list_tools(self) -> list[MCPTool]:
        return self.tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        """Return a deterministic text result shaped like an MCP tool response."""

        args = arguments or {}
        workspace = args.get("workspaceId") or "mock-workspace"
        text = {
            "Jamf_Alert_Posture_Summary": (
                f"Alert posture for {workspace}: 312 Jamf Protect alerts across 10 Mac endpoints (last 7 days).\n"
                "- Severity: 48 High, 91 Medium, 103 Low, 70 Informational\n"
                "- Prevention: 61 Prevented, 251 Allowed\n"
                "- Top event types: Process, FileSystem, Gatekeeper, USB, ProcessPrevented\n"
                "- Recommended action: pivot into Risk Profile and Prevented Execution Hunt for triage depth"
            ),
            "Jamf_Prevented_Execution_Hunt": (
                f"Prevented execution hunt for {workspace}: 61 blocked events in last 7 days.\n"
                "- Top blocked processes: osascript, python3, curl, bash, nc\n"
                "- Unsigned binaries: /tmp/payload.sh, /tmp/implant, /Users/jdoe/Downloads/Invoice.app\n"
                "- Recommended action: validate SHA256 hashes against VirusTotal and isolate affected Macs"
            ),
            "Jamf_Unsigned_Binary_Activity": (
                f"Unsigned binary activity for {workspace}: 34 distinct unsigned binaries across 7 Macs.\n"
                "- Most active: /tmp/implant (14 hits, 4 hosts), /var/folders/zz/badlib.dylib (9 hits, 3 hosts)\n"
                "- Max severity: High on /tmp/implant\n"
                "- Recommended action: review signing team IDs and block unknown binaries via Jamf Protect rules"
            ),
            "Jamf_USB_Storage_Activity": (
                f"USB activity for {workspace}: 18 USB events across 6 Macs in last 7 days.\n"
                "- 11 allowed mounts, 7 blocked (UsbBlock)\n"
                "- Most active host: finance-imac-01.contoso.local (5 USB events)\n"
                "- Recommended action: review USB policy and enforce block-by-default for non-approved serials"
            ),
            "Jamf_Mac_Endpoint_Risk_Profile": (
                f"Risk profile for {workspace}: 2 critical-risk Macs, 4 elevated, 12 baseline.\n"
                "- jdoe-mbp.contoso.local: RiskScore 87 (8 High, 3 unsigned binaries, 2 Gatekeeper events)\n"
                "- finance-imac-01.contoso.local: RiskScore 78 (6 High, 5 USB events, 1 Gatekeeper bypass)\n"
                "- Recommended action: prioritize endpoint investigation for score > 60, validate with Jamf Pro MDM"
            ),
            "Jamf_Gatekeeper_MRT_Watch": (
                f"Gatekeeper/MRT watch for {workspace}: 29 macOS native protection events in last 7 days.\n"
                "- Gatekeeper: 14 events across 6 hosts, top process: /Users/ceo/Downloads/Invoice.app\n"
                "- MRT: 8 events (XProtect signature matches), ProcessDenied: 7 events\n"
                "- Recommended action: review quarantined files and escalate repeated Gatekeeper failures to IR"
            ),
        }.get(tool_name, f"Mock result for {tool_name}:\n{json.dumps(args, indent=2)}")

        return MCPToolResult(
            tool_name=tool_name,
            content=[{"type": "text", "text": text}],
            is_error=False,
        )
