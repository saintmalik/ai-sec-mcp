# Security

`ai-sec-mcp` is a **capability auditor and MCP tool lockfile**, shipped as a local stdio MCP surface plus a CI CLI. It reads agent/MCP configs and tool declarations on disk. It does not call the network, hold API keys, execute discovered tools, or connect to the MCP servers it audits.

This is not a vulnerability scanner. It does not replace human review. Lockfile hashes catch declaration drift; they do not prove runtime behavior matches the declaration.

## Threat model (practical)

| Threat | Relevance | Posture |
|--------|-----------|---------|
| Tool poisoning (malicious descriptions) | High for audited configs | Hash lockfile fails on description drift; overbroad flags hidden-instruction cues |
| Rug pulls / dynamic tool swap | High | Fail-closed `check` / `diff_tool_lockfile` on add/remove/schema/description hash change |
| Path traversal via scan args | Medium | Workspace path sandbox; symlink escape skipped; scan depth capped |
| Credential leakage in tool results | Medium | Env secret keys redacted; result/log redaction heuristics |
| Over-privileged tools | High (as auditor) | Risk hints + overbroad patterns; does not revoke host permissions |
| Remote auth / OAuth / Confused Deputy | Low for this binary | Stdio-only; no remote HTTP transport shipped |
| Code injection via tool args | Low | No shelling out on user content; schema-typed MCP args via mcp-go |

## Transport and auth

- **STDIO only** via `server.ServeStdio` (mark3labs/mcp-go). No Streamable HTTP listener.
- Do not expose this binary on a network port.
- The host (Cursor / Claude Desktop) spawns the process; trust is process-local.

## Tool design (least privilege)

- Auditor tools are mostly read-only. Only `write_tool_lockfile` writes, and only a lockfile under (or CLI-chosen) path.
- Descriptions are factual; no system-prompt steganography in our metadata.
- **Partial supply-chain control:** content-hash lockfile (sha256 of name+description+schema), not asymmetric signatures or org approval workflows.
- **Out of scope for verification:** we inventory declared configs/manifests; we do not execute third-party MCP servers to verify behavior.

## Data validation and secrets

- mcp-go typed args; string path inputs resolved and sandboxed. No large binary outputs.
- Env maps redact sensitive keys; result text runs through secret redaction.
- Errors returned as short redacted strings. Absolute workspace paths may appear in reports by design (auditability).

## Path sandboxing

- `scan_repo` and inventory walks stay under the resolved workspace root.
- Symlinks that resolve outside the root are skipped.
- MCP `write_tool_lockfile` rejects absolute `out` paths outside the workspace. CLI may write absolute paths (e.g. `/tmp`) for CI demos by operator intent.

## Supply chain (how others should install)

Prefer pinning:

```bash
# Pin a release tag or commit when installing
go install github.com/saintmalik/ai-sec-mcp/cmd/ai-sec-mcp@v0.1.0

# Or build from a reviewed checkout
git clone https://github.com/saintmalik/ai-sec-mcp.git
cd ai-sec-mcp
git checkout v0.1.0
go build -trimpath -ldflags="-s -w" -o bin/ai-sec-mcp ./cmd/ai-sec-mcp
```

In Cursor `mcp.json`, point `command` at the **absolute binary path** you built, not an unpinned `@latest` `go run` in production.

Scan dependencies (`go mod tidy`, govulncheck / OSV) in your own CI. This project’s Action builds from source in the PR checkout.

## Out of scope

- OAuth 2.1 / OIDC, mTLS, remote Streamable HTTP
- Cryptographic signing of tool manifests (beyond sha256 hashes)
- HITL elicitations for high-risk actions (we are an auditor, not an action broker)
- Multi-tenant session isolation / quotas
- Runtime seccomp/AppArmor wrappers
- Full SIEM audit pipeline (emit JSON reports; you ship them)
- Live connection to audited MCP servers (offline, local files only)

## Reporting issues

Open a private security advisory or issue on https://github.com/saintmalik/ai-sec-mcp. Do not file public issues with live secrets.
