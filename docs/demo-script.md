# Presenter demo script

## Opener

"Jamf Protect already gives Macs world-class EDR; here's how MCP turns that telemetry into reusable agent capabilities. Instead of asking an agent to write arbitrary KQL, we publish six curated Sentinel tools that answer the questions Jamf and SOC analysts care about most."

Show the architecture in `README.md`, then explain:

1. LogSeeder creates Jamf-shaped Sentinel tables with synthetic data.
2. Each KQL file is a reviewed investigation question.
3. `scripts/publish-mcp-tools.py` publishes those queries as Sentinel MCP tools.
4. `terminal_demo.py` routes natural language prompts to the right tool.

## Setup line

Run:

```bash
MCP_DEMO_MODE=mock python3 terminal_demo.py --show-raw
```

For a live Sentinel-backed demo, use `.env` with `MCP_DEMO_MODE=real` and the workspace ID.

## Walkthrough 1: Alert posture

Sample prompt:

```text
Summarize Jamf Protect alert posture
```

Talk track:

- This selects `Jamf_Alert_Posture_Summary`.
- It answers the first analyst question: "How much Jamf Protect activity do we have, and how severe is it?"
- Point out total alerts, high/medium counts, prevented vs allowed, unique endpoints, event types, and top acting processes.

Transition:

"Now that we know there is activity, let's pivot into what Jamf actively blocked."

## Walkthrough 2: Prevented executions

Sample prompt:

```text
Hunt for prevented executions
```

Talk track:

- This selects `Jamf_Prevented_Execution_Hunt`.
- It surfaces blocked processes with command line, parent process, signer type, signing team, SHA256, and file path.
- This is the triage view an analyst wants before isolating a Mac or checking a hash.

Transition:

"Blocked execution often overlaps with unsigned or untrusted binaries, so let's group by binary path."

## Walkthrough 3: Unsigned binary activity

Sample prompt:

```text
Find unsigned binary activity
```

Talk track:

- This selects `Jamf_Unsigned_Binary_Activity`.
- It uses the DCR typo-preserved `TargetbinarySignerType` plus `TargetFileSignerType`.
- It groups by binary path and shows hit count, distinct hosts, sample command lines, max severity, and SHA256 samples.

Transition:

"Endpoint risk is not only process execution. Jamf also sees device-control style signals like USB activity."

## Walkthrough 4: USB storage activity

Sample prompt:

```text
Show USB storage events
```

Talk track:

- This selects `Jamf_USB_Storage_Activity`.
- It summarizes `USB` and `UsbBlock` events by hostname, event type, and severity.
- Call out blocked count, allowed count, device serials, and first/last seen times.

Transition:

"A SOC lead usually wants prioritization. Which Macs should we look at first?"

## Walkthrough 5: Flagship risk profile

Sample prompt:

```text
Show Mac endpoint risk profile
```

Talk track:

- This selects `Jamf_Mac_Endpoint_Risk_Profile`.
- This is the flagship tool: it ranks endpoints by a transparent `RiskScore`.
- The score combines high and medium alerts, prevented executions, unsigned binaries, Gatekeeper/MRT events, and USB events.
- Explain that Jamf could tune the weights or add VIP/device-group context in a product version.

Transition:

"Finally, let's look specifically at macOS-native protection mechanisms."

## Walkthrough 6: Gatekeeper and MRT watch

Sample prompt:

```text
Watch Gatekeeper and MRT events
```

Talk track:

- This selects `Jamf_Gatekeeper_MRT_Watch`.
- It focuses on Gatekeeper, MRT, ProcessDenied, and ProcessPrevented events.
- It groups by event type and shows hit count, distinct hosts, distinct processes, max severity, prevented count, top target processes, and sample messages.

## Closing

"The important point is not this terminal. The terminal is just the smallest possible host. The reusable asset is the MCP tool collection: reviewed KQL, clear tool descriptions, and a simple argument shape. Jamf can call the same tools from a product UI, an incident workflow, Copilot Studio, or another agent runtime. The next step is to decide which Jamf workflows should get these capabilities first, then tune the KQL and descriptions around those workflows."
