# Publish KQL files as Sentinel custom MCP tools — UI walkthrough

This repo intentionally has **no publisher script**. Instead, you save each KQL query in `mcp-tools/` as a custom Sentinel MCP tool by hand, using the **Save as tool** flow in the Microsoft Defender portal's Advanced Hunting experience.

This is the same outcome as a script-based publish, just via the UI. Use this when you want to demo the no-code path or when API publishing is not available in your tenant.

---

## Prerequisites

From the official docs:

- A workspace with **Microsoft Sentinel data lake** enabled and a **Microsoft Defender** license.
- One of these roles to create custom tools: **Security Operator**, **Security Admin**, or **Global Admin**.
- **Security Reader** or **Global Reader** to invoke them later.

Reference: [Create and use custom Microsoft Sentinel MCP tools (preview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)

---

## Step 0 — Seed the three Jamf Protect demo tables first

The KQL queries in this repo read from three custom tables that mirror the
shape produced by the official Jamf Protect CCF data connector's DCR
transform:

- `JamfProtectAlertsDemo_CL` (primary — the tools mostly target this)
- `JamfProtectTelemetryDemo_CL`
- `JamfProtectUnifiedLogsDemo_CL`

If your workspace doesn't have these tables yet, run the LogSeeder step
from the main README before continuing — otherwise the **Run** step (step 3
below) will return zero rows and the **Save as tool** option may stay
disabled.

```bash
# From the main README — once per JSON schema in logseeder/
cd "$LOGSEEDER"
pwsh ./scripts/Invoke-SampleDataIngestion.ps1 \
  -TableName JamfProtectAlertsDemo_CL \
  -Schema ./schemas/JamfProtectAlertsDemo_CL.json \
  -RowCount 400 -TimeWindowMinutes 1440 -Deploy -Ingest
# Repeat for JamfProtectTelemetryDemo_CL (RowCount 200) and
# JamfProtectUnifiedLogsDemo_CL (RowCount 150).
```

Wait 5–10 minutes for ingestion before opening Advanced Hunting.

---

## Step-by-step

Repeat steps 1–6 once **per `.kql` file** in `mcp-tools/`.

### 1. Open the Defender portal Advanced Hunting page

Go to https://security.microsoft.com → **Investigation & response** → **Hunting** → **Advanced hunting**.

### 2. Paste the KQL query

Open the matching `mcp-tools/<ToolName>.kql` file in this repo, copy the full query, and paste it into the Advanced Hunting query window.

### 3. Run the query at least once to confirm it returns rows

This validates the query against the workspace before you save it as a tool. If it returns 0 rows, top up demo data with the LogSeeder steps (step 0) before continuing.

### 4. Click **Save as tool**

Two places to find this:

- **Context menu** (right-click) on the saved query
- **KQL query box menu** (the "..." or kebab menu in the editor)

See the screenshots in the [official docs](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool#create-custom-tools-with-kql-queries).

### 5. Fill in the **Save tool** flyout

| Field | What to enter |
| --- | --- |
| **Name** | Use the `.kql` filename (without extension), e.g. `Jamf_Mac_Endpoint_Risk_Profile`. The name should be discoverable so the AI model picks the right tool. |
| **Description** | Copy the matching description from the table at the bottom of this file. |
| **Collection** | First time through, click **Create new collection** and use `Jamf-Sentinel-MCP-Demo`. After that, pick the same collection for the remaining tools. |
| **Default workspace** | Pick the workspace you seeded Jamf Protect demo data into. This becomes the default `workspaceId` used by the agent if a prompt doesn't specify one. |
| **Parameters (optional)** | Leave empty — the queries in this repo don't reference any `{ParameterName}` placeholders. |

### 6. Click **Save**

The tool is now visible in your custom MCP collection and any agent connected to that collection can call it.

---

## Verify the tools are live

After saving all six tools:

1. In the Defender portal go to **Sentinel** → **MCP** → **Tool collections** (or follow the link in the Save tool confirmation toast).
2. Confirm the collection exists with your six tools listed.
3. The collection MCP server URL is:

   ```
   https://sentinel.microsoft.com/mcp/custom/<your collection name>
   ```

   Use that URL when wiring the collection into VS Code, Copilot Studio, Foundry, or the terminal demo in this repo.

---

## Use the tools you just created

Once the tools are saved in the UI, point the included terminal demo at the collection (no script needed):

```bash
cd <this repo>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env so SENTINEL_MCP_COLLECTION matches the collection name you typed in step 5
python3 terminal_demo.py --show-raw
```

Or wire the collection into another surface using these official guides:

- [Visual Studio Code](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-visual-studio-code)
- [Microsoft Copilot Studio](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-copilot-studio)
- [Microsoft Foundry](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-azure-ai-foundry)
- [ChatGPT or Claude](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector)

---

## Useful links

- [Create and use custom Microsoft Sentinel MCP tools (preview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)
- [Tool collection in Microsoft Sentinel MCP server (overview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-tools-overview)
- [Get started with Microsoft Sentinel MCP server](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-get-started)
- [Jamf Protect Sentinel CCF connector — source DCR](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Jamf%20Protect/Data%20Connectors/JamfProtect_ccp/DCR.json)
- [Advanced hunting in Microsoft Defender](https://learn.microsoft.com/defender-xdr/advanced-hunting-microsoft-defender)

---

## Per-tool details for this repo

Suggested **collection name:** `Jamf-Sentinel-MCP-Demo`

| `.kql` file | Tool name (use as-is) | Description |
| --- | --- | --- |
| `mcp-tools/Jamf_Daily_Triage_Queue.kql` | `Jamf_Daily_Triage_Queue` | Ranked queue of dedup'd alerts the Mac SOC should review now. Each row has `TriageScore` (0–100) and a `WhyFlagged` reason array. Unions alerts + unified logs. |
| `mcp-tools/Jamf_Host_Investigation.kql` | `Jamf_Host_Investigation` | Per-host triage across alerts + unified logs + telemetry. Counts, signer mix, top processes, `UnifiedLogMessages`, `RiskHints`, and a high-signal `Timeline`. Tune the `HostFilter` let-binding. |
| `mcp-tools/Jamf_IOC_Sweep.kql` | `Jamf_IOC_Sweep` | Cross-stream indicator sweep. Given a SHA prefix / Apple Team ID / hostname fragment / process / cmdline substring, searches all three Jamf streams and returns hosts, samples, and `RecentHits`. Tune the `Indicator` let-binding. |
| `mcp-tools/Jamf_Rare_Binary_Hunt.kql` | `Jamf_Rare_Binary_Hunt` | Hunts rare, unsigned, and ad-hoc-signed binaries with `Prevalence`, `FleetPrevalencePct`, `Rarity` bucket, and `HuntReasons`. Surfaces the new-and-rare, not the common-but-noisy. |
| `mcp-tools/Jamf_USB_Anomaly_Hunt.kql` | `Jamf_USB_Anomaly_Hunt` | macOS removable-media anomaly hunt. Three discrete signals per Mac: `FirstSeenOnHost`, `RetriedAfterBlock`, `AfterHoursMount`. One row per host with `USBAnomalyScore`. |
| `mcp-tools/Jamf_Mac_Endpoint_Risk_Profile.kql` | `Jamf_Mac_Endpoint_Risk_Profile` | ★ Per-Mac risk roll-up. Synthesizes a 0–100 `RiskScore` from severity, prevented count, unsigned binaries, Gatekeeper/MRT events, and USB activity. The "which Macs first?" tool. |
| `mcp-tools/Jamf_Process_Lineage.kql` | `Jamf_Process_Lineage` | Parent-child pair analysis. Surfaces shells from GUI apps (Chrome/Office/Slack), unsigned children, ad-hoc-signed children, and rare lineages with `LineageScore` and `LineageReasons`. |
| `mcp-tools/Jamf_MITRE_ATTACK_Coverage.kql` | `Jamf_MITRE_ATTACK_Coverage` | Heuristic macOS MITRE ATT&CK rollup over alerts + unified logs. Maps to techniques like T1547.013 LaunchAgent Persistence, T1056.001 Keylogging, T1052.001 USB Exfiltration, T1059.004 Unix Shell, T1553.001 Gatekeeper Bypass. |
| `mcp-tools/Jamf_Alert_Tuning_Candidates.kql` | `Jamf_Alert_Tuning_Candidates` | SOC noise audit. High-volume, mostly-allowed, low-severity signatures with `TuningScore` and `TuningReasons` (mostly-allowed, low-severity-heavy, fleet-wide, trusted-signer, no-high-severity). |
