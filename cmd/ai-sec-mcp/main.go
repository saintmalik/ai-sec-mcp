package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/saintmalik/ai-sec-mcp/internal/inventory"
	"github.com/saintmalik/ai-sec-mcp/internal/lockfile"
	"github.com/saintmalik/ai-sec-mcp/internal/overbroad"
	"github.com/saintmalik/ai-sec-mcp/internal/redact"
	"github.com/saintmalik/ai-sec-mcp/internal/report"
	"github.com/saintmalik/ai-sec-mcp/internal/sandbox"
	"github.com/saintmalik/ai-sec-mcp/internal/scanner"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve", "mcp":
			if err := runMCP(); err != nil {
				fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
				os.Exit(1)
			}
			return
		case "scan":
			os.Exit(runScan(os.Args[2:]))
		case "list-tools":
			os.Exit(runListTools(os.Args[2:]))
		case "lock":
			os.Exit(runLock(os.Args[2:]))
		case "check":
			os.Exit(runCheck(os.Args[2:]))
		case "overbroad":
			os.Exit(runOverbroad(os.Args[2:]))
		case "report":
			os.Exit(runReport(os.Args[2:]))
		case "version", "-v", "--version":
			fmt.Printf("ai-sec-mcp %s\n", version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
			printHelp()
			os.Exit(2)
		}
	}

	// Default: stdio MCP server (Cursor / Claude Desktop entrypoint).
	if err := runMCP(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Fprintf(os.Stderr, `ai-sec-mcp %s - agent capability auditor / MCP tool lockfile

Usage:
  ai-sec-mcp                 Start stdio MCP server
  ai-sec-mcp serve           Start stdio MCP server
  ai-sec-mcp scan [path]     Find agent/MCP config files
  ai-sec-mcp list-tools [path]
  ai-sec-mcp lock [path] [--out file]
  ai-sec-mcp check [path] [--lockfile file]   Fail-closed lockfile diff (CI)
  ai-sec-mcp overbroad [path]
  ai-sec-mcp report [path] [--format md|json] [--lockfile file]
  ai-sec-mcp version

`, version)
}

func runMCP() error {
	s := server.NewMCPServer(
		"ai-sec-mcp",
		version,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// Tool descriptions are factual only (no hidden instructions in metadata).
	s.AddTool(mcp.NewTool("scan_repo",
		mcp.WithDescription("Read-only: find agent/MCP config files under a local workspace (Cursor mcp.json, Claude Desktop, VS Code, Windsurf, common patterns). Scans stay inside the given path; does not execute tools or call the network."),
		mcp.WithString("path", mcp.Description("Workspace root to scan. Defaults to process cwd. Paths outside the root are rejected.")),
	), handleScanRepo)

	s.AddTool(mcp.NewTool("list_mcp_tools",
		mcp.WithDescription("Read-only: parse configured MCP servers and known tool manifests; report tool names with write/exec/network risk hints. Env values that look like secrets are redacted."),
		mcp.WithString("path", mcp.Description("Workspace root. Defaults to cwd.")),
	), handleListTools)

	s.AddTool(mcp.NewTool("write_tool_lockfile",
		mcp.WithDescription("Write an MCP tool lockfile under the workspace (name + description/schema hashes). Output path cannot escape the workspace root. Commit the file; CI diffs against it."),
		mcp.WithString("path", mcp.Description("Workspace root. Defaults to cwd.")),
		mcp.WithString("out", mcp.Description("Output path inside the workspace. Defaults to <path>/mcp-lockfile.json.")),
	), handleWriteLockfile)

	s.AddTool(mcp.NewTool("diff_tool_lockfile",
		mcp.WithDescription("Read-only compare: current tool inventory vs a committed lockfile. Returns an error result on any drift (added/removed tools or description/schema hash changes). Fail-closed for CI."),
		mcp.WithString("path", mcp.Description("Workspace root. Defaults to cwd.")),
		mcp.WithString("lockfile", mcp.Description("Baseline lockfile path inside the workspace. Defaults to mcp-lockfile.json under path.")),
	), handleDiffLockfile)

	s.AddTool(mcp.NewTool("find_overbroad_tools",
		mcp.WithDescription("Read-only: flag dangerous capability patterns (wildcards, shell/exec, unconstrained write schemas) and description cues that look like tool poisoning."),
		mcp.WithString("path", mcp.Description("Workspace root. Defaults to cwd.")),
	), handleOverbroad)

	s.AddTool(mcp.NewTool("ci_capability_report",
		mcp.WithDescription("Read-only: produce a markdown or JSON capability report for PR comments. Does not modify the workspace."),
		mcp.WithString("path", mcp.Description("Workspace root. Defaults to cwd.")),
		mcp.WithString("format", mcp.Description("Output format: md (default) or json.")),
		mcp.WithString("lockfile", mcp.Description("Optional lockfile path inside the workspace for the drift section.")),
	), handleReport)

	return server.ServeStdio(s)
}

func resolvePath(request mcp.CallToolRequest) (string, error) {
	return sandbox.ResolveRoot(optionalString(request, "path"))
}

func optionalString(request mcp.CallToolRequest, key string) string {
	return request.GetString(key, "")
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(redact.String(err.Error())), nil
	}
	return mcp.NewToolResultText(redact.String(string(b))), nil
}

func toolErr(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(redact.String(err.Error())), nil
}

func handleScanRepo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	configs, err := scanner.ScanRepo(root)
	if err != nil {
		return toolErr(err)
	}
	return jsonResult(map[string]any{"root": root, "configs": configs})
}

func handleListTools(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	inv, err := inventory.Collect(root)
	if err != nil {
		return toolErr(err)
	}
	return jsonResult(inv)
}

func handleWriteLockfile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	out := optionalString(request, "out")
	if out != "" && filepath.IsAbs(out) && !sandbox.WithinRoot(root, out) {
		return toolErr(fmt.Errorf("out path escapes workspace root"))
	}
	lf, path, err := lockfile.Write(root, out)
	if err != nil {
		return toolErr(err)
	}
	return jsonResult(map[string]any{"written": path, "lockfile": lf})
}

func handleDiffLockfile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	lfPath := optionalString(request, "lockfile")
	diff, err := lockfile.Diff(root, lfPath)
	if err != nil {
		return toolErr(err)
	}
	b, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return toolErr(err)
	}
	text := redact.String(string(b))
	if !diff.OK {
		return mcp.NewToolResultError(text), nil
	}
	return mcp.NewToolResultText(text), nil
}

func handleOverbroad(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	findings, err := overbroad.Find(root)
	if err != nil {
		return toolErr(err)
	}
	return jsonResult(map[string]any{"root": root, "findings": findings})
}

func handleReport(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	root, err := resolvePath(request)
	if err != nil {
		return toolErr(err)
	}
	format := optionalString(request, "format")
	if format == "" {
		format = "md"
	}
	lf := optionalString(request, "lockfile")
	rep, err := report.Build(root, lf)
	if err != nil {
		return toolErr(err)
	}
	if format == "json" {
		b, err := report.ToJSON(rep)
		if err != nil {
			return toolErr(err)
		}
		return mcp.NewToolResultText(redact.String(string(b))), nil
	}
	return mcp.NewToolResultText(redact.String(report.ToMarkdown(rep))), nil
}

// --- CLI subcommands ---

func argPath(args []string) string {
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "--out" || a == "--lockfile" || a == "--format" {
			skipNext = true
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		return a
	}
	wd, _ := os.Getwd()
	return wd
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		prefix := name + "="
		if len(a) > len(prefix) && a[:len(prefix)] == prefix {
			return a[len(prefix):]
		}
	}
	return ""
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

func runScan(args []string) int {
	root := argPath(args)
	configs, err := scanner.ScanRepo(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return printJSON(map[string]any{"root": root, "configs": configs})
}

func runListTools(args []string) int {
	root := argPath(args)
	inv, err := inventory.Collect(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return printJSON(inv)
}

func runLock(args []string) int {
	root := argPath(args)
	out := flagValue(args, "--out")
	lf, path, err := lockfile.Write(root, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d tools, digest %s)\n", path, len(lf.Tools), short(lf.Digest))
	return printJSON(lf)
}

func runCheck(args []string) int {
	root := argPath(args)
	lfPath := flagValue(args, "--lockfile")
	diff, err := lockfile.Diff(root, lfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	_ = printJSON(diff)
	if !diff.OK {
		fmt.Fprintf(os.Stderr, "lockfile drift detected (%d change(s)); failing closed\n", len(diff.Drifts))
		return 1
	}
	fmt.Fprintf(os.Stderr, "lockfile OK\n")
	return 0
}

func runOverbroad(args []string) int {
	root := argPath(args)
	findings, err := overbroad.Find(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return printJSON(map[string]any{"root": root, "findings": findings})
}

func runReport(args []string) int {
	root := argPath(args)
	format := flagValue(args, "--format")
	if format == "" {
		format = "md"
	}
	lf := flagValue(args, "--lockfile")
	rep, err := report.Build(root, lf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if format == "json" {
		b, err := report.ToJSON(rep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		fmt.Println(string(b))
		return 0
	}
	fmt.Print(report.ToMarkdown(rep))
	return 0
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
