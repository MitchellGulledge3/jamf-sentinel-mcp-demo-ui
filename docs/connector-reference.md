# Jamf Protect connector reference

This reference explains how the demo maps Jamf Protect connector concepts into LogSeeder schemas and MCP tools.

## Source

Official Jamf Protect Sentinel DCR:

```text
https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Jamf%20Protect/Data%20Connectors/JamfProtect_ccp/DCR.json
```

The same URL is stored in `logseeder/source-schema-url.txt`.

## Three CCF streams

The Jamf Protect Codeless Connector Framework (CCF) connector models three useful streams for this demo:

| Stream | Demo table | Schema file | Purpose |
| --- | --- | --- | --- |
| Alerts | `JamfProtectAlertsDemo_CL` | `logseeder/JamfProtectAlertsDemo_CL.json` | High-value Jamf Protect alerts normalized toward ASIM-style columns |
| Telemetry | `JamfProtectTelemetryDemo_CL` | `logseeder/JamfProtectTelemetryDemo_CL.json` | Lower-level Endpoint Security Framework events such as process exec, file open/write, signal, mount, rename, unlink |
| UnifiedLog | `JamfProtectUnifiedLogsDemo_CL` | `logseeder/JamfProtectUnifiedLogsDemo_CL.json` | Jamf unified-log stream events with process and macOS protection context |

The MCP tools in this repository query the Alerts table because it is the most useful single table for a short developer demo. The companion telemetry and unified-log tables demonstrate how the same DCE+DCR pattern extends to additional Jamf streams.

## DCE and DCR flow

In production, Jamf Protect sends connector payloads to Azure Monitor ingestion through the CCF-managed endpoint and rule:

```text
Jamf Protect source
        -> Data Collection Endpoint (DCE)
        -> Data Collection Rule (DCR) transform
        -> Log Analytics custom table
        -> Sentinel KQL and MCP tools
```

In this demo, LogSeeder mirrors the same flow with synthetic rows:

```text
LogSeeder synthetic row generator
        -> DCE
        -> DCR generated from schema
        -> JamfProtect*Demo_CL table
        -> MCP KQL tool
```

## DCR transform and ASIM column mapping

The official DCR transform maps inbound Jamf fields into ASIM-aligned columns. The demo preserves those normalized field names so KQL written here looks like KQL that would be used against real connector data.

| Column group | Examples | Meaning |
| --- | --- | --- |
| Event identity | `EventVendor`, `EventProduct`, `EventProductVersion`, `EventOriginalUid` | Identifies Jamf Protect stream and original event |
| Event classification | `EventSeverity`, `EventOriginalType`, `EventType`, `EventResult` | Normalized alert category and outcome |
| Human-readable context | `EventMessage`, `EventResultMessage` | Alert summary and result explanation |
| Device | `DvcHostname`, `TargetHostname`, `DvcSerial`, `DvcIpAddr`, `DvcId`, `DvcOs`, `DvcOsVersion` | Mac endpoint identity and OS details |
| Process | `ActingProcessName`, `ParentProcessName`, `TargetProcessName`, `TargetProcessCommandLine` | Process chain and execution details |
| File | `TargetFilePath`, `TargetFileSHA256`, `TargetFileSignerType`, `TargetFileSigningTeamID` | File path, hash, and code signing details |
| Binary | `TargetBinaryFilePath`, `TargetBinarySHA256`, `TargetbinarySignerType`, `TargetBinarySigningTeamID` | Binary path, hash, and code signing details |
| Booleans | `TargetFileIsDownload`, `TargetFileIsAppBundle`, `TargetFileIsDirectory`, `TargetFileIsScreenshot` | Useful file attributes |

Important: `TargetbinarySignerType` uses lowercase `b`. This is intentional and preserved from the real DCR column name. Do not "fix" it to `TargetBinarySignerType` unless you also update the source DCR/table and every KQL query.

## `EventType` enum

The primary Alerts schema uses these 12 ASIM-normalized event categories:

| EventType | Meaning in the demo |
| --- | --- |
| `Click` | User click or browser-style interaction |
| `Download` | File download event |
| `FileSystem` | File create/write/rename/unlink activity |
| `Process` | General process activity |
| `Keylog` | Suspicious keylogger registration or API use |
| `Gatekeeper` | macOS Gatekeeper activity or bypass attempt |
| `MRT` | Malware Removal Tool or XProtect-style detection |
| `ProcessDenied` | Process execution denied by macOS/Jamf policy |
| `ProcessPrevented` | Process execution prevented by Jamf Protect |
| `UnifiedLog` | Unified log event surfaced as an alert |
| `USB` | USB mass storage event |
| `UsbBlock` | USB storage blocked event, including `auth-mount` style activity |

## `EventOriginalType` values and mappings

The DCR exposes Jamf-native event types in `EventOriginalType`. The demo maps them to normalized `EventType` values as follows:

| EventOriginalType | Typical normalized EventType | Notes |
| --- | --- | --- |
| `GPClickEvent` | `Click` | User interaction or click-triggered telemetry |
| `GPDownloadEvent` | `Download` | Downloaded file or browser-originated file activity |
| `GPFSEvent` | `FileSystem` | File-system operation such as write, create, rename, or unlink |
| `GPProcessEvent` | `Process` | Process creation, fork, exec, or posix spawn context |
| `GPKeylogRegisterEvent` | `Keylog` | Keylogger-style registration signal |
| `GPGatekeeperEvent` | `Gatekeeper` | Gatekeeper assessment or quarantine-related event |
| `GPMRTEvent` | `MRT` | XProtect/MRT signature or remediation signal |
| `GPPreventedExecutionEvent` | `ProcessDenied` or `ProcessPrevented` | Blocked process execution |
| `GPThreatMatchExecEvent` | `ProcessPrevented` | Threat match on execution |
| `GPUnifiedLogEvent` | `UnifiedLog` | Unified log event promoted into the alert stream |
| `GPUSBEvent` | `USB` | USB storage attach or mount event |
| `auth-mount` | `UsbBlock` | USB mount authorization/blocking outcome |

The mapping is represented as sample values in the LogSeeder schemas. Real connector deployments may include additional fields or transform logic; use the official DCR as the source of truth.

## Telemetry stream fields

`JamfProtectTelemetryDemo_CL` focuses on lower-level event stream fields:

| Field | Examples |
| --- | --- |
| `EventOriginalType` | `es_event_process_exec`, `es_event_file_open`, `es_event_file_write`, `es_event_signal`, `es_event_kextload`, `es_event_mmap`, `es_event_mount`, `es_event_rename`, `es_event_unlink`, `es_event_create` |
| `action` | `NOTIFY`, `AUTH_RESULT_ALLOW`, `AUTH_RESULT_DENY` |
| `event` | `process_exec`, `file_open`, `file_write`, `signal`, `kextload`, `mmap`, `mount`, `rename`, `unlink`, `create` |
| `process` | `bash`, `python3`, `curl`, `osascript`, `launchd`, `loginwindow`, `Finder`, `Terminal`, `node`, `ruby` |
| `thread` | Auto-generated string for demo rows |

## Unified log stream fields

`JamfProtectUnifiedLogsDemo_CL` focuses on unified-log style alert data:

| Field | Meaning |
| --- | --- |
| `EventOriginalType` | Always `GPUnifiedLogEvent` in the demo value pool |
| `EventType` | Always `UnifiedLog` in the demo value pool |
| `TargetProcessName` | Process involved in the unified log event |
| `TargetProcessCommandLine` | Example command line context |
| `EventMessage`, `EventResultMessage` | Alert and outcome descriptions |

## Practical guidance

- Keep `.json` schemas valid JSON; only `.jsonc` may contain comments.
- Use LogSeeder-generated tables for repeatable demos; use production connector tables for customer validation.
- Preserve official column names, including typos, so KQL does not drift from real data.
- Start with `Jamf_Mac_Endpoint_Risk_Profile` when showing product value because it demonstrates prioritization, not just search.
