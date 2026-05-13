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
                name="Jamf_Daily_Triage_Queue",
                description="Ranked queue of alerts a Mac SOC should review now. Dedupes per host+SHA+EventType, scores 0-100, includes WhyFlagged reasons.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_Host_Investigation",
                description="Per-host triage across alerts + unified logs + telemetry. Returns counts, signer mix, RiskHints, and a high-signal timeline.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_IOC_Sweep",
                description="Cross-stream IOC lookup. Given a SHA/TeamID/hostname/proc/cmdline indicator, sweep alerts, unified logs, and telemetry.",
                input_schema={
                    "type": "object",
                    "properties": {"workspaceId": {"type": "string"}},
                },
            ),
            MCPTool(
                name="Jamf_Rare_Binary_Hunt",
                description="Surfaces rare, unsigned, ad-hoc-signed binaries across the Mac fleet with Prevalence, Rarity bucket, and HuntReasons.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_USB_Anomaly_Hunt",
                description="macOS USB anomaly hunt: FirstSeenOnHost, RetriedAfterBlock, AfterHoursMount per Mac with USBAnomalyScore.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_Mac_Endpoint_Risk_Profile",
                description="Per-Mac risk score from severity, prevented executions, unsigned binaries, Gatekeeper events, and USB activity.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_Process_Lineage",
                description="Parent-child process pair analysis. Surfaces shells from GUI apps, unsigned children, and rare lineages with LineageScore and reasons.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_MITRE_ATTACK_Coverage",
                description="Heuristic macOS MITRE ATT&CK rollup mapped from alerts + unified logs. One row per technique with counts, hosts, and samples.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Jamf_Alert_Tuning_Candidates",
                description="SOC noise audit. High-volume, mostly-allowed, low-severity signatures that may be candidates for suppression or allowlisting.",
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
            "Jamf_Daily_Triage_Queue": (
                f"Daily triage queue for {workspace}: 50 dedup'd alert rows; top TriageScore 90.\n"
                "- #1 jdoe-mbp running python3 'sudo launchctl load /Library/LaunchAgents/com.evil.plist' (credential-access, persistence, script-interpreter)\n"
                "- #2 vip-mbp-legal running bash 'openssl s_client -connect c2.example.com:443' (credential-access, unsigned-binary, exec-prevented, high-severity)\n"
                "- #3 jdoe-mbp running curl 'curl -fsSL ... | bash' (credential-access, persistence, lolbin-allowed)\n"
                "- Recommended next: chain into Jamf_Host_Investigation for the top host"
            ),
            "Jamf_Host_Investigation": (
                f"Host investigation for {workspace}: 10 Macs in window; RiskHints surface per row.\n"
                "- vip-mbp-legal: 40 alerts (12 High), 8 unsigned execs, 1 USB block, UnifiedLog 'Keylogger registration detected'\n"
                "- finance-imac-01: 38 alerts (10 High), 6 Gatekeeper hits, after-hours USB mount\n"
                "- Recommended next: pivot suspicious SHA into Jamf_IOC_Sweep"
            ),
            "Jamf_IOC_Sweep": (
                f"IOC sweep for {workspace} (Indicator='DEADBEEF99'): 2 hosts, 3 streams matched.\n"
                "- Streams: alerts + unifiedlog + telemetry\n"
                "- Top procs: bash, python3, osascript\n"
                "- Recommended next: feed top SHA into Jamf_Process_Lineage"
            ),
            "Jamf_Rare_Binary_Hunt": (
                f"Rare binary hunt for {workspace}: 50 rare/untrusted binary groups.\n"
                "- Singleton-Untrusted: 8 binaries (e.g. perl, ruby, node, openssl on 1 host each)\n"
                "- Rare-Untrusted: 12 binaries with prevalence <= 2 hosts\n"
                "- Recommended next: triage Singleton-Untrusted first, then chain to Process_Lineage"
            ),
            "Jamf_USB_Anomaly_Hunt": (
                f"USB anomaly hunt for {workspace}: 10 Macs with USB activity; top USBAnomalyScore 75.\n"
                "- RetriedAfterBlock: 4 hosts (user retried after block fired)\n"
                "- AfterHoursMount: 6 hosts (mounts outside 07-19 UTC)\n"
                "- FirstSeenOnHost: 3 hosts (first ever USB event)\n"
                "- Recommended next: validate against Jamf Pro USB policy"
            ),
            "Jamf_Mac_Endpoint_Risk_Profile": (
                f"Risk profile for {workspace}: top RiskScore 100 on 3 hosts.\n"
                "- vip-mbp-legal, finance-imac-01, jdoe-mbp all hit ceiling — needs Host_Investigation\n"
                "- Recommended next: drop top host into Jamf_Host_Investigation"
            ),
            "Jamf_Process_Lineage": (
                f"Process lineage for {workspace}: 50 parent-child pairs ranked.\n"
                "- Top LineageScore 100: Microsoft Word -> osascript (shell-from-gui, unsigned-child)\n"
                "- Google Chrome -> bash (shell-from-gui, lolbin-allowed)\n"
                "- launchd -> openssl (rare-lineage, unsigned-child)\n"
                "- Recommended next: pivot suspicious child SHA into IOC_Sweep"
            ),
            "Jamf_MITRE_ATTACK_Coverage": (
                f"MITRE coverage for {workspace}: 15 macOS techniques observed.\n"
                "- T1547.013 LaunchAgent Persistence: 24 hits / 8 hosts\n"
                "- T1056.001 Keylogging: 18 hits / 6 hosts\n"
                "- T1059.004 Unix Shell: 42 hits / 10 hosts\n"
                "- T1052.001 USB Exfiltration: 30 hits / 9 hosts\n"
                "- Recommended next: pair with Risk_Profile for technique-to-host mapping"
            ),
            "Jamf_Alert_Tuning_Candidates": (
                f"Tuning candidates for {workspace}: 30 noisy signatures flagged.\n"
                "- FileSystem/GPFSEvent: 8 hits, 87% allowed, fleet-wide, no high-sev (mostly-allowed, low-severity-heavy, fleet-wide)\n"
                "- Process/GPProcessEvent: 6 hits, trusted Apple signer (trusted-signer, mostly-allowed)\n"
                "- Recommended next: review with Jamf Protect rules team before suppressing"
            ),
        }.get(tool_name, f"Mock result for {tool_name}:\n{json.dumps(args, indent=2)}")

        return MCPToolResult(
            tool_name=tool_name,
            content=[{"type": "text", "text": text}],
            is_error=False,
        )
