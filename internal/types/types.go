package types

import "github.com/saintmalik/ai-sec-mcp/internal/risk"

type ConfigKind string

const (
	KindCursorMCP     ConfigKind = "cursor-mcp"
	KindClaudeDesktop ConfigKind = "claude-desktop"
	KindVSCodeMCP     ConfigKind = "vscode-mcp"
	KindMCPJSON       ConfigKind = "mcp-json"
	KindWindsurf      ConfigKind = "windsurf"
	KindContinue      ConfigKind = "continue"
	KindToolManifest  ConfigKind = "tool-manifest"
	KindLockfile      ConfigKind = "lockfile"
	KindUnknown       ConfigKind = "unknown"
)

type DiscoveredConfig struct {
	Path         string     `json:"path"`
	Kind         ConfigKind `json:"kind"`
	RelativePath string     `json:"relativePath"`
}

type ToolDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"inputSchema,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	SourcePath  string `json:"sourcePath,omitempty"`
}

type McpServerConfig struct {
	Name       string            `json:"name"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	URL        string            `json:"url,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	SourcePath string            `json:"sourcePath"`
	Tools      []ToolDescriptor  `json:"tools,omitempty"`
}

type ToolInventoryEntry struct {
	ToolDescriptor
	RiskHints   []risk.Hint `json:"riskHints"`
	Fingerprint string      `json:"fingerprint"`
}

type LockfileTool struct {
	Name            string          `json:"name"`
	ServerName      string          `json:"serverName"`
	DescriptionHash string          `json:"descriptionHash"`
	SchemaHash      string          `json:"schemaHash"`
	Fingerprint     string          `json:"fingerprint"`
	RiskCategories  []risk.Category `json:"riskCategories"`
}

type ToolLockfile struct {
	Version     int            `json:"version"`
	GeneratedAt string         `json:"generatedAt"`
	SourceRoots []string       `json:"sourceRoots"`
	Tools       []LockfileTool `json:"tools"`
	Digest      string         `json:"digest"`
}

type DriftKind string

const (
	DriftAdded              DriftKind = "added"
	DriftRemoved            DriftKind = "removed"
	DriftDescriptionChanged DriftKind = "description_changed"
	DriftSchemaChanged      DriftKind = "schema_changed"
	DriftFingerprintChanged DriftKind = "fingerprint_changed"
)

type DriftEntry struct {
	Kind       DriftKind `json:"kind"`
	Name       string    `json:"name"`
	ServerName string    `json:"serverName"`
	Detail     string    `json:"detail"`
}

type DiffResult struct {
	OK             bool         `json:"ok"`
	BaselineDigest string       `json:"baselineDigest"`
	CurrentDigest  string       `json:"currentDigest"`
	Drifts         []DriftEntry `json:"drifts"`
}

type OverbroadFinding struct {
	ToolName   string        `json:"toolName"`
	ServerName string        `json:"serverName"`
	Pattern    string        `json:"pattern"`
	Severity   risk.Severity `json:"severity"`
	Detail     string        `json:"detail"`
}

type CapabilityReport struct {
	GeneratedAt   string               `json:"generatedAt"`
	Root          string               `json:"root"`
	ConfigsFound  int                  `json:"configsFound"`
	Servers       int                  `json:"servers"`
	Tools         int                  `json:"tools"`
	Overbroad     []OverbroadFinding   `json:"overbroad"`
	HighRiskTools []HighRiskTool       `json:"highRiskTools"`
	Lockfile      *LockfileReportPart  `json:"lockfile,omitempty"`
	Inventory     []ToolInventoryEntry `json:"inventory"`
}

type HighRiskTool struct {
	Name       string      `json:"name"`
	ServerName string      `json:"serverName"`
	Hints      []risk.Hint `json:"hints"`
}

type LockfileReportPart struct {
	Path   *string      `json:"path"`
	OK     *bool        `json:"ok"`
	Drifts []DriftEntry `json:"drifts"`
}
