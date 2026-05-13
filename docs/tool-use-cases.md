# Jamf Protect MCP tool use cases

This page explains what each custom Sentinel MCP tool answers, when an agent should call it, sample prompts, and the expected output shape. All tools query `JamfProtectAlertsDemo_CL` and use the real DCR typo-preserved column name `TargetbinarySignerType` where signer type is needed.

## Tool summary

| Tool | Best question | Primary output |
| --- | --- | --- |
| `Jamf_Alert_Posture_Summary` | "What is the current Jamf Protect alert posture?" | One-row posture summary |
| `Jamf_Prevented_Execution_Hunt` | "What did Jamf block?" | Up to 100 recent blocked execution rows |
| `Jamf_Unsigned_Binary_Activity` | "Where are unsigned binaries running or being blocked?" | Binary paths ranked by hit count |
| `Jamf_USB_Storage_Activity` | "Which Macs had USB storage events?" | USB events grouped by host/type/severity |
| `Jamf_Mac_Endpoint_Risk_Profile` | "Which Macs should we investigate first?" | Endpoint risk ranking |
| `Jamf_Gatekeeper_MRT_Watch` | "What did macOS-native protection catch?" | Gatekeeper/MRT protection summary |

## `Jamf_Alert_Posture_Summary`

### What it answers

- How many Jamf Protect alerts occurred in the last 7 days?
- How many were high, medium, low, prevented, or allowed?
- How many unique Mac endpoints are represented?
- Which event types and acting processes are present?
- What is the first and last seen alert time?

### When to call it

Call this as the default starting point for a Jamf Protect investigation, executive summary, health check, or demo opener.

### Sample prompt

```text
Summarize Jamf Protect alert posture
```

### Expected output shape

One row with:

| Field | Meaning |
| --- | --- |
| `TotalAlerts` | Total alert rows in the 7-day window |
| `PreventedCount`, `AllowedCount` | Action outcome counts |
| `HighAlerts`, `MediumAlerts`, `LowAlerts` | Severity counts |
| `UniqueHostnames` | Distinct affected Macs |
| `EventTypes` | Set of observed Jamf/ASIM event categories |
| `TopActingProcs` | Set of acting process names |
| `FirstSeen`, `LastSeen` | Alert time range |

## `Jamf_Prevented_Execution_Hunt`

### What it answers

- Which process executions were prevented by Jamf Protect?
- What binary hash, signer type, signing team, command line, and parent process were involved?
- Which host and file path should an analyst investigate?

### When to call it

Call this when the analyst asks about blocked, denied, prevented, or suspicious executions.

### Sample prompt

```text
Hunt for prevented executions with command line and signer details
```

### Expected output shape

Up to 100 rows ordered by newest first:

| Field | Meaning |
| --- | --- |
| `TimeGenerated` | Alert time |
| `DvcHostname` | Affected Mac |
| `TargetProcessName` | Blocked process |
| `TargetProcessSHA256` | Process hash |
| `TargetbinarySignerType` | Binary signer category |
| `TargetBinarySigningTeamID` | Apple Developer Team ID or unsigned marker |
| `TargetProcessCommandLine` | Process command line |
| `ParentProcessName` | Parent process |
| `TargetFilePath` | Related file path |
| `EventMessage`, `EventSeverity`, `EventOriginalType` | Alert context |

## `Jamf_Unsigned_Binary_Activity`

### What it answers

- Which unsigned binaries or files appeared in Jamf Protect alerts?
- How many hits and distinct hosts are associated with each binary path?
- Which command lines and SHA256 samples should be reviewed?

### When to call it

Call this for unsigned, signature, notarization, ad hoc signing, unknown developer, or signer-related prompts.

### Sample prompt

```text
Find unsigned binary activity across Macs
```

### Expected output shape

Rows grouped by `BinaryPath`:

| Field | Meaning |
| --- | --- |
| `BinaryPath` | Coalesced binary/file path |
| `HitCount` | Number of matching alerts |
| `DistinctHosts` | Unique affected Macs |
| `SampleCmdLines` | Example process command lines |
| `MaxSeverity` | Highest lexical severity in the group |
| `EventTypes` | Event categories involved |
| `AffectedHostnames` | Host samples |
| `SHA256Samples` | Hash samples |

## `Jamf_USB_Storage_Activity`

### What it answers

- Which Macs had USB storage attach or block events?
- How many were blocked versus allowed?
- Which device serials are involved?
- When were the first and last USB events seen?

### When to call it

Call this for USB, removable media, thumb drive, flash drive, mass storage, or device-control questions.

### Sample prompt

```text
Show USB storage events by host
```

### Expected output shape

Rows grouped by hostname, event type, and severity:

| Field | Meaning |
| --- | --- |
| `DvcHostname` | Affected Mac |
| `EventType` | `USB` or `UsbBlock` |
| `EventSeverity` | Alert severity |
| `EventCount` | Total matching events |
| `BlockedCount`, `AllowedCount` | Prevention split |
| `EventActions` | Observed action values |
| `DeviceSerials` | Device serial samples |
| `FirstSeen`, `LastSeen` | Time range |

## `Jamf_Mac_Endpoint_Risk_Profile` ★ Flagship

### What it answers

- Which Macs should the analyst investigate first?
- Which endpoints combine high severity, prevention, unsigned binaries, Gatekeeper/MRT events, and USB activity?
- What is the transparent risk breakdown behind the ranking?

### Why it is the flagship

This tool demonstrates the strongest product-facing MCP pattern: an analyst asks a broad prioritization question, and the tool returns a deterministic, explainable endpoint ranking. It converts many Jamf Protect signals into one sorted list that a UI, workflow, or agent can use immediately.

### When to call it

Call this for risk, score, priority, worst Mac, highest-risk endpoint, VIP endpoint, or triage-order prompts.

### Sample prompt

```text
Show Mac endpoint risk profile and rank the riskiest endpoints
```

### Expected output shape

Up to 50 hosts ordered by `RiskScore`:

| Field | Meaning |
| --- | --- |
| `DvcHostname` | Mac endpoint |
| `RiskScore` | Score capped at 100 |
| `TotalAlerts` | Total alert volume |
| `HighCount`, `MediumCount` | Severity drivers |
| `PreventedCount` | Jamf-blocked activity |
| `UnsignedBinaryCount` | Unsigned binary/file indicators |
| `GatekeeperBypassCount` | Gatekeeper/MRT activity |
| `USBEventCount` | USB signals |
| `UniqueTargetProcs` | Process diversity |
| `OsVersion` | macOS version |
| `AlertTypes`, `SampleMessages` | Explainability context |
| `LastAlertTime` | Recency |

### Customization ideas

- Add Jamf Pro smart group membership or VIP tags.
- Increase risk weights for executive or finance devices.
- Add MITRE ATT&CK technique labels.
- Suppress known-good developer team IDs.
- Split the score into prevention, code-signing, persistence, and device-control dimensions.

## `Jamf_Gatekeeper_MRT_Watch`

### What it answers

- What activity did macOS-native protections detect or prevent?
- Which event type is most common: Gatekeeper, MRT, ProcessDenied, or ProcessPrevented?
- How many hosts and target processes are involved?

### When to call it

Call this for Gatekeeper, XProtect, MRT, quarantine, process denied, process prevented, or native macOS protection prompts.

### Sample prompt

```text
Watch Gatekeeper and MRT events across the fleet
```

### Expected output shape

Rows grouped by `EventType`:

| Field | Meaning |
| --- | --- |
| `EventType` | Protection event category |
| `HitCount` | Event count |
| `DistinctHosts` | Affected Macs |
| `DistinctProcs` | Distinct target process names |
| `MaxSeverity` | Highest severity |
| `PreventedCount` | Blocked/prevented count |
| `TopTargetProcs` | Target process samples |
| `AffectedHosts` | Host samples |
| `SampleMessages` | Human-readable alert samples |

## Agent routing guidance

For an agent or product router, prefer specific tools when the user's intent is clear:

1. Risk/prioritization -> `Jamf_Mac_Endpoint_Risk_Profile`.
2. Prevention/blocking -> `Jamf_Prevented_Execution_Hunt`.
3. Code signing -> `Jamf_Unsigned_Binary_Activity`.
4. USB/removable media -> `Jamf_USB_Storage_Activity`.
5. Gatekeeper/XProtect/MRT -> `Jamf_Gatekeeper_MRT_Watch`.
6. General or ambiguous -> `Jamf_Alert_Posture_Summary`.
