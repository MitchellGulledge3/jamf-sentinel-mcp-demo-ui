# Live working session guide

Use this guide when a Microsoft advisor and a Jamf developer are on a call together. The goal is to leave the call with the developer understanding the pattern and knowing exactly where to customize it for Jamf's own platform.

## Outcome

By the end, you should have:

| Outcome | Proof |
| --- | --- |
| Demo data in Sentinel | `JamfProtectAlertsDemo_CL`, `JamfProtectTelemetryDemo_CL`, and `JamfProtectUnifiedLogsDemo_CL` return rows |
| Custom MCP tools published | Six Jamf tools exist in the MCP collection |
| Terminal demo working | Prompts return Sentinel-backed or mock results |
| Platform integration path understood | Developer knows which code to reuse in Jamf's platform |

## Roles

| Person | Owns |
| --- | --- |
| Microsoft advisor | Azure/Sentinel setup, MCP publishing, explaining the pattern |
| Jamf developer | Reviewing schema, KQL, tool names, and platform integration fit |

## Step 0: Confirm access

Run:

```bash
az account show
```

Confirm:

| Check | Why |
| --- | --- |
| Correct tenant | Tokens must come from the tenant with Sentinel access |
| Correct subscription | LogSeeder creates Azure resources in this subscription |
| Sentinel workspace exists | The demo writes and queries data there |
| You can publish MCP tools | Needed for the custom tool collection |

If this fails, run:

```bash
az login
az account set --subscription "<subscription-id-or-name>"
```

## Step 1: Clone the repo

```bash
git clone https://github.com/<owner>/jamf-sentinel-mcp-demo.git
cd jamf-sentinel-mcp-demo
export REPO_ROOT=$(pwd)
```

Show these files first:

| File | What to explain |
| --- | --- |
| `logseeder/JamfProtectAlertsDemo_CL.json` | Primary demo table schema based on the official Jamf Protect Sentinel DCR |
| `logseeder/JamfProtectAlertsDemo_CL.annotated.jsonc` | Human-readable comments explaining column groups |
| `mcp-tools/` | The KQL queries that become MCP tools |
| `terminal_demo.py` | The simple prompt loop that calls the tools |

## Step 2: Prepare Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```text
MCP_DEMO_MODE=real
SENTINEL_MCP_COLLECTION=Jamf-Sentinel-MCP-Demo
SENTINEL_MCP_TOOL=Jamf_Daily_Triage_Queue
MCP_TOOL_ARGUMENT_TEMPLATE={}
MCP_DEFAULT_ARGUMENTS={"workspaceId":"<log-analytics-workspace-customer-id>"}
```

The `workspaceId` is the Log Analytics workspace customer ID, not the Azure resource ID.

## Step 3: Seed demo data

Copy the schemas into your LogSeeder repo:

```bash
export LOGSEEDER=/path/to/sentinel-logseeder
cp ./logseeder/JamfProtectAlertsDemo_CL.json "$LOGSEEDER/schemas/"
cp ./logseeder/JamfProtectTelemetryDemo_CL.json "$LOGSEEDER/schemas/"
cp ./logseeder/JamfProtectUnifiedLogsDemo_CL.json "$LOGSEEDER/schemas/"
cd "$LOGSEEDER"
```

Run LogSeeder for alerts (400 rows):

```bash
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/Invoke-SampleDataIngestion.ps1 \
  -TableName JamfProtectAlertsDemo_CL \
  -Schema ./schemas/JamfProtectAlertsDemo_CL.json \
  -RowCount 400 \
  -TimeWindowMinutes 10080 \
  -Deploy -Ingest
```

Run LogSeeder for telemetry (200 rows):

```bash
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/Invoke-SampleDataIngestion.ps1 \
  -TableName JamfProtectTelemetryDemo_CL \
  -Schema ./schemas/JamfProtectTelemetryDemo_CL.json \
  -RowCount 200 \
  -TimeWindowMinutes 10080 \
  -Deploy -Ingest
```

Run LogSeeder for unified logs (150 rows):

```bash
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/Invoke-SampleDataIngestion.ps1 \
  -TableName JamfProtectUnifiedLogsDemo_CL \
  -Schema ./schemas/JamfProtectUnifiedLogsDemo_CL.json \
  -RowCount 150 \
  -TimeWindowMinutes 10080 \
  -Deploy -Ingest
```

What this does:

| Resource | Plain-English meaning |
| --- | --- |
| Tables | Where the Jamf demo rows live |
| DCE | The ingestion endpoint |
| DCR | The mapping rule that sends fields into the tables |

## Step 4: Verify with KQL

Run these checkpoint queries in Sentinel:

```kql
JamfProtectAlertsDemo_CL
| summarize RowCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
```

```kql
JamfProtectTelemetryDemo_CL
| summarize RowCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
```

```kql
JamfProtectUnifiedLogsDemo_CL
| summarize RowCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
```

Stop here until each `RowCount` is greater than zero. If it is zero, wait a few minutes and query again.

Useful investigation checks:

```kql
JamfProtectAlertsDemo_CL
| summarize Alerts=count(), Hosts=dcount(DvcHostname), Severities=make_set(EventSeverity, 10), Types=make_set(EventType, 20)
```

```kql
JamfProtectAlertsDemo_CL
| where TargetbinarySignerType == "Unsigned" or TargetFileSignerType == "Unsigned"
| summarize Hits=count(), Hosts=dcount(DvcHostname) by TargetBinaryFilePath
| order by Hits desc
```

## Step 5: Publish MCP tools

Return to this repo:

```bash
cd "$REPO_ROOT"
```

Publish:

```bash
python3 scripts/publish-mcp-tools.py \
  --collection Jamf-Sentinel-MCP-Demo \
  --workspace-id "<workspace-customer-id>"
```

Explain this simply:

> Each `.kql` file becomes one custom MCP tool. The tool is a safe, reusable question over the Sentinel table.

## Step 6: Run the terminal demo

Run real mode:

```bash
python3 terminal_demo.py --show-raw
```

Or run offline mock mode if Azure connectivity is not ready:

```bash
MCP_DEMO_MODE=mock python3 terminal_demo.py --show-raw
```

Paste these prompts:

```text
Summarize Jamf Protect alert posture
Hunt for prevented executions
Find unsigned binary activity
Show USB storage events
Show Mac endpoint risk profile
Watch Gatekeeper and MRT events
```

Checkpoint:

| Prompt | Success looks like |
| --- | --- |
| Alert posture | Alert count, severity counts, prevented count, unique hosts |
| Prevented executions | Blocked process names, signer type, SHA256, command line |
| Unsigned binaries | Binary paths, hit counts, affected hosts |
| USB storage | Allowed vs blocked USB activity and serials |
| Risk profile | Endpoints ranked by `RiskScore` |
| Gatekeeper/MRT | Native macOS protection events grouped by type |

## Step 7: Show where Jamf would customize

| Area | File | Jamf decision |
| --- | --- | --- |
| Real schema/table | `logseeder/*.json` | Use demo tables, real connector tables, or customer tables |
| Tool logic | `mcp-tools/*.kql` | Which investigations should Jamf package? |
| Tool descriptions | `scripts/publish-mcp-tools.py` | How should tools appear to agents? |
| Prompt routing | `terminal_demo.py` | Which user phrases map to which tools? |
| Platform integration | `sentinel_mcp_demo/client.py` | Reuse the MCP client pattern inside Jamf's app |

## Platform integration path

For Jamf's platform, the terminal demo becomes:

```text
Jamf UI prompt or button
        ->
Jamf backend chooses an MCP tool
        ->
Sentinel MCP tool runs curated KQL
        ->
Jamf UI shows summary, rows, and next action
```

The reusable code is mostly:

| Code | Reuse |
| --- | --- |
| `sentinel_mcp_demo/client.py` | MCP initialize, list tools, call tool, parse result |
| `mcp-tools/*.kql` | Security questions to productize |
| `scripts/publish-mcp-tools.py` | Tool publishing pattern |
| `terminal_demo.py` | Prompt routing and result summarization pattern |

## Fast troubleshooting

| Problem | What to do |
| --- | --- |
| `az` auth fails | Run `az login`, then set the right subscription |
| LogSeeder succeeds but no rows | Wait and rerun the query |
| MCP publish fails | Confirm account can manage Sentinel MCP tool collections |
| Terminal demo has no workspace | Fix `MCP_DEFAULT_ARGUMENTS` in `.env` |
| Tool returns no rows | Re-seed data or widen the query window |
| Mock mode works but real mode fails | Separate terminal code from Sentinel MCP auth and collection publishing issues |

## Suggested close

Ask the Jamf developer which two or three investigations are most valuable in their product workflow. Then update the KQL and descriptions together so the MCP tool names match the way Jamf analysts actually ask questions.
