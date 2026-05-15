# Jamf Sentinel MCP Demo (UI variant — superseded)

> ⚠️ **This repo is no longer the recommended starting point.**
> Engineering has approved publishing MCP tools via the **Sentinel custom MCP API** for ISV reference implementations.
> Use the API-based repo going forward:
>
> 👉 **[jamf-sentinel-mcp-demo](https://github.com/mgulledge_microsoft/jamf-sentinel-mcp-demo)**

---

## Why this repo still exists

This repo was shared with Jamf (and other partners) when the recommended publish path was to register each MCP tool by hand in the Microsoft Defender portal (UI). We're leaving it in place so any link already shared still works, but the API path is what we now run with.

The `mcp-tools/*.kql` content is identical between the two repos. The only difference is the publish mechanism:

- **This repo (UI variant)** — register each tool manually in the Microsoft Defender portal.
- **[jamf-sentinel-mcp-demo](https://github.com/mgulledge_microsoft/jamf-sentinel-mcp-demo)** — one-command idempotent publish via the Sentinel custom MCP API (`scripts/publish-mcp-tools.py`). Scriptable, re-runnable, and works as part of an ISV's CI/CD or solution-deploy step.

Both paths produce the same MCP collection registered against the customer's Sentinel workspace. The API path is the eng-approved approach going forward; the UI path remains valid if a partner prefers it.

## Where to go next

- **Recommended:** [jamf-sentinel-mcp-demo](https://github.com/mgulledge_microsoft/jamf-sentinel-mcp-demo) — the API-publish reference implementation we're running with.
- **Architecture, tools, seed data, working-session guide:** all live in the API repo above. This repo's docs may drift over time and should be considered frozen.
