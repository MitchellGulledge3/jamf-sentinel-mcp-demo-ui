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
    "posture": "Jamf_Alert_Posture_Summary",
    "prevented": "Jamf_Prevented_Execution_Hunt",
    "unsigned": "Jamf_Unsigned_Binary_Activity",
    "usb": "Jamf_USB_Storage_Activity",
    "risk": "Jamf_Mac_Endpoint_Risk_Profile",
    "gatekeeper": "Jamf_Gatekeeper_MRT_Watch",
}

TOOL_ROUTES = [
    (("prevent", "blocked", "denied", "execution blocked"), JAMF_TOOLS["prevented"]),
    (("unsigned", "signature", "notariz", "ad hoc", "signer"), JAMF_TOOLS["unsigned"]),
    (("usb", "removable", "thumb drive", "mass storage", "flash drive"), JAMF_TOOLS["usb"]),
    (("risk", "score", "worst mac", "vip", "highest risk", "risky"), JAMF_TOOLS["risk"]),
    (("gatekeeper", "xprotect", "mrt", "quarantine", "process denied", "process prevented"), JAMF_TOOLS["gatekeeper"]),
]

EXAMPLE_PROMPTS = [
    "Summarize Jamf Protect alert posture",
    "Hunt for prevented executions",
    "Find unsigned binary activity",
    "Show USB storage events",
    "Show Mac endpoint risk profile",
    "Watch Gatekeeper and MRT events",
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
    return configured or JAMF_TOOLS["posture"]


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
    if tool_name == JAMF_TOOLS["prevented"]:
        return (
            f"Prevented execution hunt: {row.get('DvcHostname')} — process {row.get('TargetProcessName')} "
            f"was blocked. Signer: {row.get('TargetbinarySignerType')}. "
            f"Command: {row.get('TargetProcessCommandLine')}. "
            f"Parent: {row.get('ParentProcessName')}."
        )
    if tool_name == JAMF_TOOLS["unsigned"]:
        return (
            f"Unsigned binary activity: {row.get('BinaryPath')} — "
            f"{row.get('HitCount')} hits across {row.get('DistinctHosts')} hosts. "
            f"Max severity: {row.get('MaxSeverity')}. "
            f"Sample command: {row.get('SampleCmdLines')}."
        )
    if tool_name == JAMF_TOOLS["usb"]:
        return (
            f"USB activity: {row.get('DvcHostname')} — {row.get('EventType')} event "
            f"({row.get('EventCount')} times). Severity: {row.get('EventSeverity')}. "
            f"Serials: {row.get('DeviceSerials')}."
        )
    if tool_name == JAMF_TOOLS["risk"]:
        return (
            f"Mac risk profile: {row.get('DvcHostname')} has RiskScore {row.get('RiskScore')}. "
            f"High alerts: {row.get('HighCount')}, prevented: {row.get('PreventedCount')}, "
            f"unsigned binaries: {row.get('UnsignedBinaryCount')}, "
            f"Gatekeeper events: {row.get('GatekeeperBypassCount')}. "
            f"OS: {row.get('OsVersion')}."
        )
    if tool_name == JAMF_TOOLS["gatekeeper"]:
        return (
            f"Gatekeeper/MRT watch: {row.get('EventType')} — {row.get('HitCount')} hits "
            f"across {row.get('DistinctHosts')} hosts and {row.get('DistinctProcs')} distinct processes. "
            f"Prevented: {row.get('PreventedCount')}. "
            f"Top processes: {row.get('TopTargetProcs')}."
        )
    return (
        f"Alert posture: {row.get('TotalAlerts')} Jamf Protect alerts across "
        f"{row.get('UniqueHostnames')} Mac endpoints. "
        f"High: {row.get('HighAlerts')}, Prevented: {row.get('PreventedCount')}. "
        f"Event types: {row.get('EventTypes')}."
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
