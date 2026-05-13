# Presenter demo script

## Opener

"Jamf Protect already gives Macs world-class EDR; here's how MCP turns that telemetry into reusable SOC and agent capabilities. Instead of asking an agent to write arbitrary KQL, we publish nine curated Sentinel tools that answer the questions a Mac SOC asks every day — designed to chain together so an agent can move from 'what should I look at?' to 'here's the incident report' in one conversation."

Show the architecture in `README.md`, then explain:

1. LogSeeder creates Jamf-shaped Sentinel tables with synthetic data (alerts, telemetry, unified logs).
2. Each KQL file is a reviewed investigation question.
3. `scripts/publish-mcp-tools.py` publishes those queries as Sentinel MCP tools.
4. `terminal_demo.py` routes natural language prompts to the right tool.

## Setup line

Run:

```bash
MCP_DEMO_MODE=mock python3 terminal_demo.py --show-raw
```

For a live Sentinel-backed demo, use `.env` with `MCP_DEMO_MODE=real` and the workspace ID.

## Walkthrough 1: Daily triage queue (start here)

Sample prompt:

```text
What should I triage today?
```

Talk track:

- This selects `Jamf_Daily_Triage_Queue`.
- It dedups alerts per host+SHA+EventType, scores each row with a 0-100 `TriageScore`, and returns a `WhyFlagged` reason array (credential-access, persistence, unsigned-binary, exec-prevented, ...).
- Point out the top row's hostname, command line, and reason codes — explain that the agent doesn't have to re-derive logic to summarize.

Transition: "Let's pick the top host and pivot."

## Walkthrough 2: Host investigation

Sample prompt:

```text
Deep dive on vip-mbp-legal
```

Talk track:

- This selects `Jamf_Host_Investigation`.
- It unions all three Jamf streams (alerts + unified logs + telemetry) into one host view.
- Highlight `RiskHints`, the `UnifiedLogMessages` (analyst-friendly text like "Keylogger registration detected"), and the 15-event `Timeline`.
- This replaces 4-5 separate KQL queries an analyst would normally hand-write.

Transition: "Suspicious SHA in the timeline — let's sweep for it."

## Walkthrough 3: IOC sweep

Sample prompt:

```text
IOC sweep for team id DEADBEEF99
```

Talk track:

- This selects `Jamf_IOC_Sweep`.
- One call hits all three streams. The agent gets `StreamsMatched`, `HostsAffected`, and a `RecentHits` array.
- Demo the let-binding pattern: inside Advanced Hunting, change `Indicator = ""` to a SHA, TeamID, hostname, process name, or cmdline substring.

Transition: "What spawned this? Let's look at the lineage."

## Walkthrough 4: Process lineage

Sample prompt:

```text
Show suspicious process lineages
```

Talk track:

- This selects `Jamf_Process_Lineage`.
- Surfaces shells/scripts spawned by GUI apps (Chrome, Office, Slack, Zoom), unsigned children, ad-hoc-signed children, and rare lineages.
- Top result is usually something like `loginwindow -> nc` or `Microsoft Word -> osascript` with `LineageScore` 100.

Transition: "We have the answer. Let's frame it for the SOC lead."

## Walkthrough 5: Risk profile ★

Sample prompt:

```text
Which Macs need investigation first?
```

Talk track:

- This is the flagship tool: `Jamf_Mac_Endpoint_Risk_Profile`.
- Per-Mac `RiskScore` combining severity, prevented executions, unsigned binaries, Gatekeeper/MRT events, and USB events.
- Top 3 hosts (vip-mbp-legal, finance-imac-01, jdoe-mbp) are the SOC's "investigate first" list.

## Walkthrough 6: Rare binary hunt

Sample prompt:

```text
Find rare or unsigned binaries
```

Talk track:

- This selects `Jamf_Rare_Binary_Hunt`.
- Replaces a flat "list every unsigned thing" with prevalence-aware rarity buckets.
- `Singleton-Untrusted` is the highest-priority bucket: one host, unsigned or ad-hoc-signed.

## Walkthrough 7: USB anomaly hunt

Sample prompt:

```text
USB anomalies on the Mac fleet
```

Talk track:

- This selects `Jamf_USB_Anomaly_Hunt`.
- Three discrete signals per Mac: `FirstSeenOnHost`, `RetriedAfterBlock`, `AfterHoursMount`.
- Top row (`finance-imac-01`) tripped all three — that's the SOC's "go look" row.

## Walkthrough 8: MITRE ATT&CK coverage

Sample prompt:

```text
MITRE ATT&CK coverage this week
```

Talk track:

- This selects `Jamf_MITRE_ATTACK_Coverage`.
- Heuristic mapping over alerts + unified logs to macOS techniques (T1547.013 LaunchAgent Persistence, T1056.001 Keylogging, T1052.001 USB Exfiltration, T1059.004 Unix Shell, T1553.001 Gatekeeper Bypass).
- Useful for executive briefings, coverage reviews, and ATT&CK navigator inputs.

## Walkthrough 9: Tuning candidates

Sample prompt:

```text
Which Mac detections are noisy and tunable?
```

Talk track:

- This selects `Jamf_Alert_Tuning_Candidates`.
- The "noise audit". Finds high-volume, mostly-allowed, low-severity signatures with trusted signers.
- Each row carries `TuningReasons` so the SOC has a one-glance justification before touching a detection rule.

## Closing

"The point isn't the terminal. The terminal is just the smallest possible host. The reusable asset is the MCP tool collection: reviewed KQL, clear descriptions, an agent-friendly argument shape, and reason codes (`WhyFlagged`, `RiskHints`, `HuntReasons`, `LineageReasons`, `USBReasons`, `TuningReasons`) that let an LLM summarize without re-deriving logic. Jamf can call the same tools from a product UI, an incident workflow, Copilot Studio, or another agent runtime."
