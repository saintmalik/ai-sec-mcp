# ai-sec-mcp

Agent capability auditor and MCP tool lockfile.

Scans a repo for MCP configs (Cursor, Claude Desktop, VS Code, and common neighbors). Locks tool names plus hashes of description and schema. CI fails on a new tool or a description/schema change. Flags overbroad tools (wildcards, unrestrained shell/exec). Offline, local files only. No live connection to the servers being audited.

This is not a vulnerability scanner. It does not "solve OWASP." It is not a data MCP you point an agent at for app secrets. It is a control that watches other MCP configs and tool declarations, then fails closed on drift.

## Install

```bash
go install github.com/saintmalik/ai-sec-mcp/cmd/ai-sec-mcp@latest
```

Prefer a pinned version or absolute binary path in production (see [SECURITY.md](SECURITY.md)).

### Cursor (`mcp.json`)

Project: `.cursor/mcp.json` or user: `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ai-sec-mcp": {
      "command": "ai-sec-mcp"
    }
  }
}
```

From a local checkout after `go build -o ai-sec-mcp ./cmd/ai-sec-mcp`, point `command` at the absolute binary path.

### Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ai-sec-mcp": {
      "command": "ai-sec-mcp"
    }
  }
}
```

## CLI

```bash
go build -o ai-sec-mcp ./cmd/ai-sec-mcp

# Inventory configs
./ai-sec-mcp scan .

# List tools + risk hints
./ai-sec-mcp list-tools .

# Write lockfile (commit this)
./ai-sec-mcp lock . --out mcp-lockfile.json

# Fail-closed drift check (exit 1 on drift)
./ai-sec-mcp check . --lockfile mcp-lockfile.json

# Overbroad patterns
./ai-sec-mcp overbroad .

# PR-ready report
./ai-sec-mcp report . --format md
```

Default with no subcommand starts the local stdio MCP surface for the same auditor tools (optional; CI should use the CLI/Action).

## Auditor tools (CLI and optional MCP)

| Tool | Purpose |
| --- | --- |
| `scan_repo` | Find Cursor/Claude/VS Code/common MCP config files |
| `list_mcp_tools` | Parse configured servers + manifests; tool names + write/exec/network hints |
| `write_tool_lockfile` | Write `mcp-lockfile.json` (name + description/schema hashes) |
| `diff_tool_lockfile` | Diff inventory vs lockfile; fail on drift |
| `find_overbroad_tools` | Flag wildcards, shell/exec, unconstrained write patterns |
| `ci_capability_report` | Markdown/JSON report for PR comments |

## GitHub Action

```yaml
- uses: saintmalik/ai-sec-mcp/action@main
  with:
    path: .
    lockfile: mcp-lockfile.json
```

Reusable workflow:

```yaml
jobs:
  capabilities:
    uses: saintmalik/ai-sec-mcp/.github/workflows/lockfile-check.yml@main
    with:
      lockfile: mcp-lockfile.json
```

Exit code is non-zero when the lockfile drifts (fail-closed). See also `.github/workflows/ci.yml`.

## Typical flow

1. Put MCP configs (and optional `tool-manifest.json`) in the repo.
2. Run `ai-sec-mcp lock .` and commit `mcp-lockfile.json`.
3. Gate PRs with the Action or `ai-sec-mcp check`.
4. When adding a tool on purpose, update the lockfile in the same PR.

Example policy sketch: [`examples/policy.example.json`](examples/policy.example.json).

## How inventory works

The auditor reads **declared** tools from:

- Inline `tools` arrays in MCP JSON configs
- Nearby manifests (`tool-manifest.json`, `tools.json`, `mcp-tools.json`)

It does not spawn remote MCP servers. Servers without declarations show up with zero tools. That keeps CI deterministic and offline.

## Bad-PR fixtures (demo)

```bash
go test ./...

# New write tool sneaks in -> check fails
./ai-sec-mcp lock ./fixtures/clean --out /tmp/lock.json
./ai-sec-mcp check ./fixtures/bad-new-write-tool --lockfile /tmp/lock.json
# exit 1, drift kind: added (write_file)

# Description/schema drift -> check fails
./ai-sec-mcp check ./fixtures/bad-schema-drift --lockfile /tmp/lock.json
# exit 1, drift kinds: schema_changed / description_changed
```

Fixtures:

- `fixtures/clean`: baseline read-only docs tools
- `fixtures/bad-new-write-tool`: sneaky `write_file` with unconstrained path
- `fixtures/bad-schema-drift`: same tool names, changed schema/description

## License

Apache-2.0
