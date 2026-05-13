# Jamf Protect MCP tool use cases

This page explains what each MCP tool answers, when an agent (or SOC analyst)
should call it, sample prompts, and the expected output shape. Every tool
preserves the real DCR column name `TargetbinarySignerType` (lowercase `b`).

## Tool summary

| Tool | Best question | Primary output |
| --- | --- | --- |
| `Jamf_Daily_Triage_Queue` | "What should I look at on Macs right now?" | Ranked queue of dedup'd alert rows with `TriageScore` + `WhyFlagged` |
| `Jamf_Host_Investigation` | "Tell me everything about host X" | Per-host stats across all 3 Jamf streams + timeline |
| `Jamf_IOC_Sweep` | "Have we seen this SHA / TeamID / process / cmdline anywhere?" | Cross-stream hit summary + `RecentHits` |
| `Jamf_Rare_Binary_Hunt` | "What rare or unsigned binaries are running?" | Rare binaries with `Rarity` bucket + `HuntReasons` |
| `Jamf_USB_Anomaly_Hunt` | "Any suspicious removable-media activity?" | Per-host USB anomaly signals + `USBAnomalyScore` |
| `Jamf_Mac_Endpoint_Risk_Profile` | "Which Macs are riskiest?" ★ | Per-Mac `RiskScore` ranking |
| `Jamf_Process_Lineage` | "What's spawning what?" | Parent-child pairs with `LineageScore` + reasons |
| `Jamf_MITRE_ATTACK_Coverage` | "What ATT&CK techniques fired this week?" | One row per technique with hits + hosts |
| `Jamf_Alert_Tuning_Candidates` | "Which detections are noisy and tunable?" | Signatures with `TuningScore` + reasons |

## Agent chaining

The tools are designed to compose. A common SOC investigation flow:

```
Jamf_Daily_Triage_Queue  ─┐
                          ├─→ pick the top host
Jamf_Host_Investigation ←─┘   (set HostFilter let-binding)
        │
        ↓ find a suspicious SHA / TeamID
Jamf_IOC_Sweep                (set Indicator let-binding)
        │
        ↓ identify the lineage
Jamf_Process_Lineage
        │
        ↓ frame the incident
Jamf_MITRE_ATTACK_Coverage
```

For weekly review, pair `Jamf_Mac_Endpoint_Risk_Profile` (who) with
`Jamf_MITRE_ATTACK_Coverage` (what) and `Jamf_Alert_Tuning_Candidates`
(noise reduction).

---

## `Jamf_Daily_Triage_Queue`

**What it answers**

- What alerts should the Mac SOC look at right now?
- Why is each row on the queue (credential-access, persistence, unsigned-binary,
  exec-prevented, lolbin-allowed, script-interpreter, high-severity)?

**When to call it**

First call of the day, or any "top alerts", "what's on the queue", "what
should I triage" prompt. Default starting point for an agent investigation.

**Sample prompt**

```text
What should I triage on the Mac fleet today?
```

**Output shape**

Up to 50 rows ranked by `TriageScore` (0-100), each with `WhyFlagged`
(dynamic array of reason codes), `MaxSeverity`, `Result`, `DvcHostname`,
`EventType`, `TargetProcessName`, `CmdLine`, `SignerType`, `TeamID`,
`HitCount` (dedup count), `FirstSeen`, `LastSeen`, `SampleMessage`, `SHA`.

---

## `Jamf_Host_Investigation`

**What it answers**

- For this Mac, what's the alert count, severity mix, signer mix, top
  processes, top parents, Gatekeeper hits, USB activity, distinct SHAs,
  distinct TeamIDs?
- What does the unified log stream say about this host?
- How much telemetry has this host produced?
- What's the chronological order of high-signal events?

**When to call it**

After picking a row off the triage queue. Or when a user asks "tell me about
X", "investigate X", "deep dive X", "what's happening on X".

**Sample prompt**

```text
Deep dive on vip-mbp-legal
```

Inside Advanced Hunting, scope by editing the let-binding:

```kql
let HostFilter = "vip-mbp-legal";
```

**Output shape**

Up to 25 rows (one per host), each with `AlertCount`, `HighAlertCount`,
`PreventedCount`, `UnsignedExecCount`, `AdHocExecCount`, `GatekeeperHits`,
`UsbEventCount`, `DistinctSHAs`, `DistinctTeamIDs`, `TopTargetProcs`,
`TopParents`, `SignerTypesSeen`, `TeamIDsSeen`, `UnifiedLogHighCount`,
`UnifiedLogMessages` (analyst-friendly), `UnifiedLogTopProcs`,
`TelemetryRowCount`, `TelemetryEventTypes`, `TelemetryActions`,
`TelemetryProcs`, `RiskHints`, and a 15-event `Timeline`.

---

## `Jamf_IOC_Sweep`

**What it answers**

- Have we seen this SHA256 prefix / Apple Team ID / hostname / process /
  command-line substring anywhere across alerts + unified logs + telemetry?

**When to call it**

When an agent has been handed an IOC. When TI lookup returns a hit. When
investigating a Defender alert that references a Mac SHA.

**Sample prompt**

```text
IOC sweep for team id DEADBEEF99
```

Inside Advanced Hunting:

```kql
let Indicator = "DEADBEEF99";   // SHA prefix, TeamID, hostname, proc, cmdline
```

**Output shape**

A single summary row plus a `RecentHits` array (up to 30 events). Includes
`TotalHits`, `HostsAffected`, `HostSet`, `StreamsMatched`, `EventTypes`,
`Severities`, `Results`, `SampleProcs`, `SampleSHAs`, `SampleTeamIDs`,
`SignerTypes`, `SampleCmdLines`, `SampleDetails`, `FirstSeen`, `LastSeen`,
and the original `Indicator` value.

---

## `Jamf_Rare_Binary_Hunt`

**What it answers**

- What binaries are rare and untrusted across the Mac fleet?
- Which are singletons (one host)?
- Which are unsigned or ad-hoc-signed *and* low-prevalence?

**When to call it**

Threat hunting, weekly review, or after `Jamf_Alert_Tuning_Candidates`
identifies trusted noise so the rare-and-new signal isn't drowned out.

**Sample prompt**

```text
Find rare or unsigned binaries on Macs
```

**Output shape**

Up to 50 rows. Each row is one (process, signer-type) group with
`RarityScore`, `Rarity` bucket (Singleton-Untrusted, Rare-Untrusted,
Untrusted-Widespread, Singleton, Rare, Low-Prevalence), `Prevalence`
(host count), `FleetPrevalencePct`, `AppearanceCount`, `AllowedCount`,
`PreventedCount`, `HighCount`, `HuntReasons`, `TeamIDs`, `Parents`,
`SampleCmdLines`, `SampleSHAs`, `HostSet`, `FirstSeen`, `LastSeen`.

---

## `Jamf_USB_Anomaly_Hunt`

**What it answers**

- Which Macs had their first USB event in the lookback window?
- Where did a user retry after a UsbBlock fired?
- Where were mounts outside 07:00-19:00 UTC?

**When to call it**

USB or removable-media prompts. Insider-risk reviews. After-hours suspicious
activity hunts.

**Sample prompt**

```text
Show USB anomalies on the Mac fleet
```

**Output shape**

Up to ~25 rows (one per host with USB activity). Each row has
`USBAnomalyScore`, `USBReasons`, `UsbEventCount`, `MountCount`, `BlockCount`,
`PreventedCount`, `AllowedCount`, `AfterHoursCount`, `FirstSeenOnHost`,
`RetriedAfterBlock`, `AfterHoursMount`, `MaxSeverity`, `MacSerial`,
`OsVersion`, `FirstWindowEvent`, `LastWindowEvent`, and a 10-event
`Timeline`.

---

## `Jamf_Mac_Endpoint_Risk_Profile` ★

**What it answers**

- Which Macs should we investigate first?
- What's the per-Mac mix of severity, prevented executions, unsigned
  binaries, Gatekeeper/MRT events, and USB activity?

**When to call it**

Flagship demo tool. Executive briefings. Daily standup. When a user asks
"which Macs are risky", "where should we focus", "worst Mac", "VIP risk".

**Sample prompt**

```text
Which Macs need investigation first?
```

**Output shape**

Up to 50 rows ranked by `RiskScore` (0-100), with `TotalAlerts`,
`HighCount`, `MediumCount`, `PreventedCount`, `UnsignedBinaryCount`,
`GatekeeperBypassCount`, `USBEventCount`, `UniqueTargetProcs`, `OsVersion`,
`AlertTypes`, `SampleMessages`, `LastAlertTime`.

---

## `Jamf_Process_Lineage`

**What it answers**

- Which parent-child process pairs look like macOS attacker tradecraft?
- Where is a shell or scripting interpreter being spawned by a GUI app
  (Chrome, Office, Slack, Zoom)?
- Where are unsigned or ad-hoc-signed children running?

**When to call it**

After an IOC sweep returns a process. When investigating a single host. When
answering "what spawned X" or "process tree" prompts.

**Sample prompt**

```text
Show suspicious process lineages
```

**Output shape**

Up to 50 rows. Each row is one (parent, child) pair with `LineageScore`,
`LineageReasons` (shell-from-gui, unsigned-child, adhoc-child, rare-lineage,
high-severity), `PairCount`, `DistinctHosts`, `AllowedCount`, `PreventedCount`,
`HighCount`, `UnsignedCount`, `AdHocCount`, `HostSet`, `SignerTypes`,
`TeamIDs`, `Severities`, `SampleCmdLines`, `SampleSHAs`, `FirstSeen`,
`LastSeen`.

---

## `Jamf_MITRE_ATTACK_Coverage`

**What it answers**

- Which macOS ATT&CK techniques fired this week?
- How many hits, how many hosts, what's the severity mix?

Mapped techniques include:

- T1204 User Execution
- T1547.013 Boot or Logon Autostart: LaunchAgent/LaunchDaemon
- T1547.015 Boot or Logon Autostart: Login Items
- T1056.001 Input Capture: Keylogging
- T1052.001 Exfiltration Over USB
- T1059.004 Unix Shell
- T1059.002 AppleScript
- T1059.006 Python
- T1071.001 Application Layer Protocol: Web Protocols
- T1553.001 Subvert Trust Controls: Gatekeeper Bypass
- T1555.001 Credentials from Password Stores: Keychain
- T1574 Hijack Execution Flow
- T1027 Obfuscated Files or Information
- T1083 File and Directory Discovery
- T1105 Ingress Tool Transfer
- T1204.002 User Execution: Malicious File

**When to call it**

Executive briefings. Coverage reviews. ATT&CK navigator inputs. Quarterly
detection efficacy reports.

**Sample prompt**

```text
What MITRE ATT&CK techniques are firing on Macs this week?
```

**Output shape**

One row per Technique with `CoverageScore`, `HitCount`, `HostsAffected`,
`HostSet`, `HighCount`, `MediumCount`, `LowCount`, `PreventedCount`,
`AllowedCount`, `Streams`, `EventTypes`, `TopProcs`, `SampleMessages`,
`FirstSeen`, `LastSeen`.

---

## `Jamf_Alert_Tuning_Candidates`

**What it answers**

- Which Jamf Protect signatures fire often but are almost always allowed
  and low-severity?
- Which fire fleet-wide on trusted signers and may belong on an allowlist?

**When to call it**

Weekly tuning reviews. Agent-driven false-positive triage. After an
on-call rotation that flagged too many low-fidelity pages.

**Sample prompt**

```text
Which Mac detections are noisy and tunable?
```

**Output shape**

Up to 30 rows (one per noisy EventType + EventOriginalType pair). Each row
has `TuningScore` (0-100), `TuningReasons` (mostly-allowed, low-severity-heavy,
fleet-wide, trusted-signer, no-high-severity), `HitCount`, `DistinctHosts`,
`AllowedRatio`, `HighRatio`, `LowRatio`, `AllowedCount`, `PreventedCount`,
`HighCount`, `MediumCount`, `LowOrInfoCount`, `SignerTypes`, `TeamIDs`,
`SampleProcs`, `SampleCmdLines`, `FirstSeen`, `LastSeen`.
