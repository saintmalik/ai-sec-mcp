# Architecture

`ai-sec-mcp` is a local agent capability auditor and MCP tool lockfile. No cloud APIs. No god-keys.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Config scanner  │────▶│ Tool inventory   │────▶│ Lockfile + diff │
│ (mcp.json, …)   │     │ + risk hints     │     │ fail-closed     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                   │
                                   ▼
                        ┌──────────────────┐
                        │ Overbroad rules  │
                        │ + CI report      │
                        └──────────────────┘
```

## Surfaces

| Surface | Role |
| --- | --- |
| Optional stdio MCP surface (`ai-sec-mcp` default / `serve`) | Same auditor tools for Cursor / Claude Desktop hosts |
| CLI (`ai-sec-mcp scan\|lock\|check\|…`) | Same core for CI and local scripts |
| GitHub Action / reusable workflow | Fail-closed lockfile gate on PRs |

Implementation: Go module `github.com/saintmalik/ai-sec-mcp` with `mcp-go` stdio transport.

## Data sources

- Project MCP configs: `.cursor/mcp.json`, `mcp.json`, `.vscode/mcp.json`, Claude Desktop-style configs, Continue, Windsurf paths
- Inline `tools` arrays inside those configs
- Nearby manifests: `tool-manifest.json`, `tools.json`, `mcp-tools.json`

The auditor does **not** spawn configured MCP servers to discover live tools. If a server has no declared tools or nearby manifest, it appears as a server with zero tools. That keeps CI offline and deterministic.

## Lockfile model

Each tool is locked by:

- `serverName` + `name`
- `descriptionHash` (SHA-256 of trimmed description)
- `schemaHash` (SHA-256 of stably serialized input schema)
- composite `fingerprint`

`diff_tool_lockfile` fails on add, remove, description drift, or schema drift.

## Risk and overbroad heuristics

Labels are triage signals from names, descriptions, and schema shape (`write` / `exec` / `network` / `read`). They are not a vulnerability scanner and do not prove exploitability.

## Security

See [SECURITY.md](SECURITY.md) for threat model, path sandbox, redaction, and supply-chain install notes.

## Why Go

Single static binary, fast CI cold start, no Node runtime on the critical path. MCP stdio via [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go); same packages power `ai-sec-mcp check`.
