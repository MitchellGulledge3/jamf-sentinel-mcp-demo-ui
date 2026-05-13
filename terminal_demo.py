from __future__ import annotations

"""Interactive terminal demo for the Jamf Protect Sentinel MCP tools.

This replaces the earlier browser demo with the lowest-friction presenter flow:
run one Python command, type normal investigation prompts, and show the tool
selection, arguments, concise summary, and raw Sentinel MCP result in the same
terminal window.
"""

import argparse
import asyncio
import json
import os
from typing import Any

from dotenv import load_dotenv

from sentinel_mcp_demo.client import MCPToolResult, SentinelMCPClient
from sentinel_mcp_demo.mock import MockSentinelMCPClient


JAMF_TOOLS = {
    "triage":   "Jamf_Daily_Triage_Queue",
    "host":     "Jamf_Host_Investigation",
    "ioc":      "Jamf_IOC_Sweep",
    "rare":     "Jamf_Rare_Binary_Hunt",
    "usb":      "Jamf_USB_Anomaly_Hunt",
    "risk":     "Jamf_Mac_Endpoint_Risk_Profile",
    "lineage":  "Jamf_Process_Lineage",
    "mitre":    "Jamf_MITRE_ATTACK_Coverage",
    "tuning":   "Jamf_Alert_Tuning_Candidates",
}

TOOL_ROUTES = [
    (("triage", "queue", "top alerts", "what should i look at", "today"), JAMF_TOOLS["triage"]),
    (("host", "investigate", "tell me about", "deep dive", "everything"), JAMF_TOOLS["host"]),
    (("ioc", "sweep", "have we seen", "indicator", "sha256", "team id", "teamid"), JAMF_TOOLS["ioc"]),
    (("rare", "unsigned", "signature", "notariz", "ad hoc", "ad-hoc", "signer", "first seen", "singleton"), JAMF_TOOLS["rare"]),
    (("usb", "removable", "thumb drive", "mass storage", "flash drive", "after hours"), JAMF_TOOLS["usb"]),
    (("risk", "score", "worst mac", "vip", "highest risk", "risky"), JAMF_TOOLS["risk"]),
    (("lineage", "parent", "child", "spawned", "process tree", "shell from"), JAMF_TOOLS["lineage"]),
    (("mitre", "att&ck", "attack", "technique", "coverage", "tactic"), JAMF_TOOLS["mitre"]),
    (("tuning", "noisy", "suppress", "allowlist", "false positive", "fp", "tune"), JAMF_TOOLS["tuning"]),
]

EXAMPLE_PROMPTS = [
    "What should I triage today?",
    "Deep dive on vip-mbp-legal",
    "IOC sweep for team id DEADBEEF99",
    "Find rare or unsigned binaries",
    "USB anomalies on the Mac fleet",
    "Show Mac endpoint risk profile",
    "Show suspicious process lineages",
    "MITRE ATT&CK coverage this week",
    "Which alerts are noisy and tunable?",
]


def parse_json_env(name: str, default: dict[str, Any]) -> dict[str, Any]:
    """Read an environment variable that must contain a JSON object."""

    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object.")
    return value


def render_arguments(message: str, template: str, defaults: dict[str, Any]) -> dict[str, Any]:
    """Render the prompt into the MCP argument template and merge defaults."""

    rendered = template.replace("{message}", message)
    try:
        args = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP_TOOL_ARGUMENT_TEMPLATE rendered invalid JSON: {exc}") from exc
    if not isinstance(args, dict):
        raise ValueError("MCP_TOOL_ARGUMENT_TEMPLATE must render to a JSON object.")
    return {**args, **defaults}


def select_tool(prompt: str) -> str:
    """Choose the Jamf MCP tool that best matches the typed prompt."""

    configured = os.getenv("SENTINEL_MCP_TOOL", "").strip()
    prompt_lower = prompt.lower()
    for keywords, tool_name in TOOL_ROUTES:
        if any(keyword in prompt_lower for keyword in keywords):
            return tool_name
    return configured or JAMF_TOOLS["triage"]


def create_mcp_client() -> SentinelMCPClient | MockSentinelMCPClient:
    """Create either the real Sentinel MCP client or the offline mock client."""

    mode = os.getenv("MCP_DEMO_MODE", "mock").strip().lower()
    if mode == "real":
        return SentinelMCPClient(
            collection=os.getenv("SENTINEL_MCP_COLLECTION"),
            server_url=os.getenv("SENTINEL_MCP_SERVER_URL"),
        )
    if mode == "mock":
        return MockSentinelMCPClient()
    raise ValueError("MCP_DEMO_MODE must be 'mock' or 'real'.")


def dataset_rows(result: MCPToolResult) -> list[dict[str, Any]]:
    """Extract Kusto PrimaryResult rows from the raw MCP text content."""

    rows: list[dict[str, Any]] = []
    for item in result.content:
        if item.get("type") != "text":
            continue
        text = str(item.get("text", ""))
        try:
            frames = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(frames, list):
            continue
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
            continue
        columns = [column.get("ColumnName", "") for column in primary.get("Columns", [])]
        for row in primary.get("Rows", []):
            rows.append({columns[index]: value for index, value in enumerate(row) if index < len(columns)})
    return rows


def summarize(prompt: str, tool_name: str, rows: list[dict[str, Any]], raw_text: str) -> str:
    """Create a presenter-friendly summary from the first returned row."""

    if not rows:
        return raw_text or f"{tool_name} completed for: {prompt}"

    row = rows[0]
    if tool_name == JAMF_TOOLS["triage"]:
        return (
            f"Daily triage queue (top row): TriageScore {row.get('TriageScore')} — "
            f"{row.get('DvcHostname')} running {row.get('TargetProcessName')} "
            f"({row.get('EventType')}, severity {row.get('MaxSeverity')}). "
            f"WhyFlagged: {row.get('WhyFlagged')}. "
            f"Sample message: {row.get('SampleMessage')}."
        )
    if tool_name == JAMF_TOOLS["host"]:
        return (
            f"Host investigation: {row.get('DvcHostname')} — {row.get('AlertCount')} alerts "
            f"({row.get('HighAlertCount')} High), {row.get('UnsignedExecCount')} unsigned execs, "
            f"{row.get('UsbEventCount')} USB events, {row.get('GatekeeperHits')} Gatekeeper/MRT. "
            f"RiskHints: {row.get('RiskHints')}. OS: {row.get('OsVersion')}."
        )
    if tool_name == JAMF_TOOLS["ioc"]:
        return (
            f"IOC sweep (indicator='{row.get('Indicator')}'): {row.get('TotalHits')} hits across "
            f"{row.get('HostsAffected')} hosts. Streams: {row.get('StreamsMatched')}. "
            f"First seen {row.get('FirstSeen')}, last seen {row.get('LastSeen')}."
        )
    if tool_name == JAMF_TOOLS["rare"]:
        return (
            f"Rare binary hunt (top row): {row.get('TargetProcessName')} ({row.get('SignerType')}) — "
            f"Rarity={row.get('Rarity')}, Prevalence={row.get('Prevalence')} hosts "
            f"({row.get('FleetPrevalencePct')}% of fleet). HuntReasons: {row.get('HuntReasons')}."
        )
    if tool_name == JAMF_TOOLS["usb"]:
        return (
            f"USB anomaly: {row.get('DvcHostname')} — USBAnomalyScore {row.get('USBAnomalyScore')}. "
            f"FirstSeenOnHost={row.get('FirstSeenOnHost')}, "
            f"RetriedAfterBlock={row.get('RetriedAfterBlock')}, "
            f"AfterHoursMount={row.get('AfterHoursMount')}. "
            f"USBReasons: {row.get('USBReasons')}."
        )
    if tool_name == JAMF_TOOLS["risk"]:
        return (
            f"Mac risk profile: {row.get('DvcHostname')} has RiskScore {row.get('RiskScore')}. "
            f"High alerts: {row.get('HighCount')}, prevented: {row.get('PreventedCount')}, "
            f"unsigned binaries: {row.get('UnsignedBinaryCount')}, "
            f"Gatekeeper events: {row.get('GatekeeperBypassCount')}. "
            f"OS: {row.get('OsVersion')}."
        )
    if tool_name == JAMF_TOOLS["lineage"]:
        return (
            f"Process lineage: {row.get('ParentProcessName')} -> {row.get('TargetProcessName')} "
            f"({row.get('PairCount')} occurrences across {row.get('DistinctHosts')} hosts). "
            f"LineageScore {row.get('LineageScore')}. Reasons: {row.get('LineageReasons')}."
        )
    if tool_name == JAMF_TOOLS["mitre"]:
        return (
            f"MITRE ATT&CK: {row.get('Technique')} — {row.get('HitCount')} hits across "
            f"{row.get('HostsAffected')} hosts. Severity mix: "
            f"High={row.get('HighCount')}, Med={row.get('MediumCount')}, Low={row.get('LowCount')}. "
            f"Streams: {row.get('Streams')}."
        )
    if tool_name == JAMF_TOOLS["tuning"]:
        return (
            f"Tuning candidate: {row.get('EventType')}/{row.get('EventOriginalType')} — "
            f"{row.get('HitCount')} hits, {row.get('AllowedRatio')}% allowed, "
            f"{row.get('DistinctHosts')} hosts. TuningScore {row.get('TuningScore')}. "
            f"Reasons: {row.get('TuningReasons')}."
        )
    return (
        f"{tool_name} result: {json.dumps({k: row.get(k) for k in list(row)[:6]}, default=str)}"
    )


async def run_prompt(prompt: str, *, show_raw: bool) -> None:
    """Call the selected MCP tool once and print the result."""

    tool_name = select_tool(prompt)
    template = os.getenv("MCP_TOOL_ARGUMENT_TEMPLATE", '{"query":"{message}"}')
    defaults = parse_json_env("MCP_DEFAULT_ARGUMENTS", {})
    arguments = render_arguments(prompt, template, defaults)

    print(f"\nPrompt: {prompt}")
    print(f"Tool:   {tool_name}")
    print(f"Args:   {json.dumps(arguments, sort_keys=True)}")
    print("Status: calling Sentinel MCP...\n")

    client = create_mcp_client()
    await client.connect()
    try:
        result = await client.call_tool(tool_name, arguments)
    finally:
        await client.close()

    rows = dataset_rows(result)
    raw_text = result.text or json.dumps(result.content, indent=2)
    print("Summary")
    print("-------")
    print(summarize(prompt, tool_name, rows, raw_text))

    if show_raw:
        print("\nRaw MCP result")
        print("--------------")
        print(raw_text)


async def interactive_loop(show_raw: bool) -> None:
    """Run the live terminal prompt loop until the presenter exits."""

    print("Jamf Protect Sentinel MCP Terminal Demo")
    print("Type a prompt and press Enter. Type 'examples' to list prompts or 'quit' to exit.\n")
    print("Examples:")
    for prompt in EXAMPLE_PROMPTS:
        print(f"  - {prompt}")

    while True:
        try:
            prompt = input("\njamf-mcp> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not prompt:
            continue
        if prompt.lower() in {"quit", "exit", "q"}:
            return
        if prompt.lower() == "examples":
            for example in EXAMPLE_PROMPTS:
                print(f"  - {example}")
            continue

        try:
            await run_prompt(prompt, show_raw=show_raw)
        except Exception as exc:
            print(f"Error: {exc}")


def main() -> None:
    """Load configuration, parse flags, and start the terminal demo."""

    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the Jamf Protect Sentinel MCP terminal demo.")
    parser.add_argument("--prompt", help="Run one prompt and exit instead of starting the interactive loop.")
    parser.add_argument("--show-raw", action="store_true", help="Print the formatted raw MCP/Kusto result.")
    args = parser.parse_args()

    if args.prompt:
        asyncio.run(run_prompt(args.prompt, show_raw=args.show_raw))
    else:
        asyncio.run(interactive_loop(show_raw=args.show_raw))


if __name__ == "__main__":
    main()
