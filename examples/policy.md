# Example policy

Commit `mcp-lockfile.json` at the repo root.

Rules that work with this tool today:

1. **Fail closed on drift.** PRs that add, remove, or change tool description/schema hashes must update the lockfile in the same change and explain why.
2. **Treat new write/exec tools as high risk.** `find_overbroad_tools` and risk hints are triage aids; require human approval before merging shell/exec or unconstrained write tools.
3. **No silent manifest changes.** Inline tools in `.cursor/mcp.json` and nearby `tools.json` / `mcp-tools.json` are part of the inventory.

This file is documentation only. Enforcement is `ai-sec-mcp check` in CI.
