# Sample tool runs

These are the actual JSON responses returned by each MCP tool when run live
against a Microsoft Sentinel workspace seeded with **400 Jamf Protect alert
rows, 200 telemetry rows, and 150 unified-log rows** via LogSeeder.

- Workspace region: `westus2`
- Run date: 2026-05-13
- Tables: `JamfProtectAlertsDemo_CL` (primary), `JamfProtectTelemetryDemo_CL`,
  `JamfProtectUnifiedLogsDemo_CL`
- Per-tool raw JSON: [`docs/sample-runs/`](./sample-runs/)

Use these as a reference for what each tool returns so you can:
1. Validate your own LogSeeder run produced comparable output before
   publishing the tools.
2. Show partners / customers concrete evidence the demo works end-to-end.
3. Wire up downstream Security Copilot prompts against a known response
   shape.

---

## 1. `Jamf_Alert_Posture_Summary`

Executive roll-up of every Jamf Protect alert in the workspace.

```json
{
  "AllowedCount": "191",
  "PreventedCount": "209",
  "TotalAlerts": "400",
  "HighAlerts": "97",
  "MediumAlerts": "90",
  "LowAlerts": "104",
  "UniqueHostnames": "10",
  "EventTypes": ["FileSystem","USB","Click","UsbBlock","Gatekeeper","UnifiedLog","Download","MRT","ProcessPrevented","ProcessDenied","Process","Keylog"],
  "TopActingProcs": ["zsh","ssh","sh","sudo","Terminal","bash","osascript","mdmclient","openssl","Zoom"],
  "FirstSeen": "2026-05-12T20:36:28Z",
  "LastSeen":  "2026-05-13T20:26:55Z"
}
```

**Highlights:** 400 alerts across 10 Macs, 12 distinct `EventType`s, 209
prevented vs 191 allowed — the "are we connected and seeing meaningful
volume" status check.

---

## 2. `Jamf_Prevented_Execution_Hunt`

Top 100 prevented execution events with full process / file / signing
context preserved for analyst pivot. Returned **100 rows**.

```json
{
  "TimeGenerated": "2026-05-13T20:24:58Z",
  "DvcHostname": "vip-mbp-legal.contoso.local",
  "DvcOsVersion": "macOS 14.4.1",
  "EventType": "ProcessPrevented",
  "EventSeverity": "High",
  "EventMessage": "Unsigned binary execution",
  "EventResultMessage": "Blocked by Jamf Protect (XProtect signature match)",
  "TargetProcessName": "osascript",
  "TargetProcessSHA256": "<sha256>",
  "TargetProcessCommandLine": "osascript -e 'do shell script ...'",
  "TargetProcessCurrentDirectory": "/usr/bin",
  "TargetFilePath": "/tmp/payload.dylib",
  "TargetFileSignerType": "Unsigned",
  "TargetFileSigningTeamID": "(unsigned)",
  "ParentProcessName": "bash"
}
```

Full payload in [`sample-runs/Jamf_Prevented_Execution_Hunt.json`](./sample-runs/Jamf_Prevented_Execution_Hunt.json).

---

## 3. `Jamf_Unsigned_Binary_Activity`

Top 10 unsigned binaries / files seen running on Macs in the workspace.

```json
{
  "TargetIdentifier": "/tmp/payload.dylib",
  "HitCount": "42",
  "DistinctHosts": "7",
  "MaxSeverity": "High",
  "PreventedCount": "24",
  "SampleCommandLines": ["osascript -e 'do shell script ...'","python3 -c 'import os...'","bash -c 'echo ...'"]
}
```

Each row aggregates by file path with hit count, host fan-out, max
severity, and prevented count — gives a SOC a single-table "where is
the unsigned-code risk concentrated?" answer.

---

## 4. `Jamf_USB_Storage_Activity`

USB mount / block activity. **41 rows** returned (one per
host × action × serial).

```json
{
  "DvcHostname": "intern-mbp-01.contoso.local",
  "Action": "USB",
  "DvcSerial": "C02DK4567ABC",
  "MaxSeverity": "Medium",
  "EventCount": "3",
  "FirstSeen": "2026-05-13T01:14:22Z",
  "LastSeen":  "2026-05-13T19:55:01Z"
}
```

---

## 5. `Jamf_Mac_Endpoint_Risk_Profile` ★ flagship

Per-host risk roll-up. Score = `min(100, 10×High + 5×Medium +
8×Unsigned + 5×GatekeeperBypass + 3×USB + 2×Prevented)`. **Top 10 Macs**
returned by RiskScore.

```json
[
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
    "SampleMessages": ["Unsigned binary execution","Process injection observed","TCC database access","USB mass storage attached","Office macro spawn"]
  },
  {
    "DvcHostname": "finance-imac-01.contoso.local",
    "RiskScore": "100",
    "TotalAlerts": "44",
    "HighCount": "6",
    "MediumCount": "10",
    "PreventedCount": "16",
    "UnsignedBinaryCount": "13",
    "GatekeeperBypassCount": "9",
    "OsVersion": "macOS 13.6.1"
  },
  {
    "DvcHostname": "jdoe-mbp.contoso.local",
    "RiskScore": "100",
    "TotalAlerts": "43",
    "HighCount": "14",
    "UnsignedBinaryCount": "16"
  }
]
```

This is the row that turns "we have a Jamf feed in Sentinel" into "we
have a Jamf-driven SOC view" — the answer a TPM and a SOC lead can both
point at on day one.

---

## 6. `Jamf_Gatekeeper_MRT_Watch`

macOS-native protection mechanism activity, grouped by `EventType`:
**Gatekeeper, MRT, ProcessDenied, ProcessPrevented**. 4 rows (one per
category).

```json
[
  {
    "EventType": "ProcessDenied",
    "HitCount": "40",
    "PreventedCount": "25",
    "DistinctHosts": "9",
    "DistinctProcs": "18",
    "MaxSeverity": "Medium",
    "TopTargetProcs": ["osascript","mdmclient","ruby","Slack","Microsoft Word"]
  },
  {
    "EventType": "Gatekeeper",
    "HitCount": "35",
    "DistinctHosts": "10",
    "TopTargetProcs": ["zsh","launchd","perl","loginwindow","Safari"]
  },
  {
    "EventType": "MRT",
    "HitCount": "34"
  },
  {
    "EventType": "ProcessPrevented",
    "HitCount": "..."
  }
]
```

The four-row shape is the right level of abstraction for a daily Mac-SOC
standup: "what are XProtect/Gatekeeper/MRT actually catching this week?"
