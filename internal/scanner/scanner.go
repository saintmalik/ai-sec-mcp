package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/saintmalik/ai-sec-mcp/internal/redact"
	"github.com/saintmalik/ai-sec-mcp/internal/sandbox"
	"github.com/saintmalik/ai-sec-mcp/internal/types"
)

type knownPath struct {
	Rel  string
	Kind types.ConfigKind
}

var knownPaths = []knownPath{
	{".cursor/mcp.json", types.KindCursorMCP},
	{"mcp.json", types.KindMCPJSON},
	{".mcp.json", types.KindMCPJSON},
	{".vscode/mcp.json", types.KindVSCodeMCP},
	{"claude_desktop_config.json", types.KindClaudeDesktop},
	{".claude/claude_desktop_config.json", types.KindClaudeDesktop},
	{"windsurf/mcp_config.json", types.KindWindsurf},
	{".windsurf/mcp.json", types.KindWindsurf},
	{".continue/config.json", types.KindContinue},
	{"mcp-lockfile.json", types.KindLockfile},
	{".ai-sec/mcp-lockfile.json", types.KindLockfile},
	{"ai-sec-lockfile.json", types.KindLockfile},
}

var manifestNames = map[string]struct{}{
	"tools.json":         {},
	"mcp-tools.json":     {},
	"tool-manifest.json": {},
	"mcp-manifest.json":  {},
}

var skipDirs = map[string]struct{}{
	"node_modules": {},
	".git":         {},
	"dist":         {},
	"coverage":     {},
	".next":        {},
	"vendor":       {},
}

// ScanRepo finds agent/MCP config files under root.
// Paths that escape the workspace (via .. or symlink) are skipped.
func ScanRepo(root string) ([]types.DiscoveredConfig, error) {
	absRoot, err := sandbox.ResolveRoot(root)
	if err != nil {
		return nil, err
	}
	found := map[string]types.DiscoveredConfig{}

	for _, p := range knownPaths {
		full := filepath.Join(absRoot, filepath.FromSlash(p.Rel))
		if !sandbox.WithinRoot(absRoot, full) {
			continue
		}
		if fileExists(full) {
			found[full] = types.DiscoveredConfig{
				Path:         full,
				Kind:         p.Kind,
				RelativePath: p.Rel,
			}
		}
	}

	_ = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !sandbox.WithinRoot(absRoot, path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			return nil
		}
		if depth := strings.Count(rel, string(os.PathSeparator)); depth > sandbox.MaxScanDepth && d.IsDir() {
			return filepath.SkipDir
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		kind := types.KindUnknown
		switch {
		case name == "mcp.json" || name == ".mcp.json":
			switch {
			case strings.Contains(rel, ".cursor"):
				kind = types.KindCursorMCP
			case strings.Contains(rel, ".vscode"):
				kind = types.KindVSCodeMCP
			default:
				kind = types.KindMCPJSON
			}
		case name == "claude_desktop_config.json":
			kind = types.KindClaudeDesktop
		case name == "mcp-lockfile.json" || name == "ai-sec-lockfile.json":
			kind = types.KindLockfile
		default:
			if _, ok := manifestNames[name]; ok {
				kind = types.KindToolManifest
			} else {
				return nil
			}
		}
		found[path] = types.DiscoveredConfig{
			Path:         path,
			Kind:         kind,
			RelativePath: filepath.ToSlash(rel),
		}
		return nil
	})

	out := make([]types.DiscoveredConfig, 0, len(found))
	for _, c := range found {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RelativePath < out[j].RelativePath
	})
	return out, nil
}

// ParseServersFromConfig extracts MCP server entries from a config file.
func ParseServersFromConfig(cfg types.DiscoveredConfig) ([]types.McpServerConfig, error) {
	if cfg.Kind == types.KindLockfile {
		return nil, nil
	}
	raw, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil
	}

	if cfg.Kind == types.KindToolManifest {
		return parseManifestAsServer(obj, cfg.Path), nil
	}
	if cfg.Kind == types.KindContinue {
		return parseContinueConfig(obj, cfg.Path), nil
	}

	mcpServers := firstMap(obj, "mcpServers", "servers", "mcp")
	if mcpServers == nil {
		return nil, nil
	}

	var out []types.McpServerConfig
	for name, value := range mcpServers {
		v, ok := value.(map[string]any)
		if !ok {
			continue
		}
		srv := types.McpServerConfig{
			Name:       name,
			SourcePath: cfg.Path,
			Tools:      extractInlineTools(v, name, cfg.Path),
		}
		if c, ok := v["command"].(string); ok {
			srv.Command = c
		}
		if u, ok := v["url"].(string); ok {
			srv.URL = u
		}
		if args, ok := v["args"].([]any); ok {
			for _, a := range args {
				if s, ok := a.(string); ok {
					srv.Args = append(srv.Args, s)
				}
			}
		}
		if env, ok := v["env"].(map[string]any); ok {
			raw := map[string]string{}
			for ek, ev := range env {
				if s, ok := ev.(string); ok {
					raw[ek] = s
				}
			}
			// Never return secret values to the model.
			srv.Env = redact.EnvMap(raw)
		}
		out = append(out, srv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// LoadNearbyManifests loads sibling/known tool manifests.
func LoadNearbyManifests(root string, servers []types.McpServerConfig) ([]types.ToolDescriptor, error) {
	absRoot, err := sandbox.ResolveRoot(root)
	if err != nil {
		return nil, err
	}
	candidates := []string{
		filepath.Join(absRoot, "tools.json"),
		filepath.Join(absRoot, "mcp-tools.json"),
		filepath.Join(absRoot, "tool-manifest.json"),
		filepath.Join(absRoot, ".ai-sec", "tools.json"),
	}
	for _, srv := range servers {
		dir := filepath.Dir(srv.SourcePath)
		candidates = append(candidates,
			filepath.Join(dir, "tools.json"),
			filepath.Join(dir, srv.Name+".tools.json"),
			filepath.Join(dir, "mcp-tools.json"),
		)
	}

	seen := map[string]struct{}{}
	var tools []types.ToolDescriptor
	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		if !fileExists(c) {
			continue
		}
		raw, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		serverName := filepath.Base(filepath.Dir(c))
		if s, ok := obj["serverName"].(string); ok {
			serverName = s
		}
		var toolsRaw any = obj
		if t, ok := obj["tools"]; ok {
			toolsRaw = t
		}
		tools = append(tools, extractToolsArray(toolsRaw, serverName, c)...)
	}
	return tools, nil
}

func parseManifestAsServer(obj map[string]any, sourcePath string) []types.McpServerConfig {
	serverName := "manifest"
	if s, ok := obj["serverName"].(string); ok {
		serverName = s
	} else if s, ok := obj["name"].(string); ok {
		serverName = s
	}
	var toolsRaw any = obj
	if t, ok := obj["tools"]; ok {
		toolsRaw = t
	}
	return []types.McpServerConfig{{
		Name:       serverName,
		SourcePath: sourcePath,
		Tools:      extractToolsArray(toolsRaw, serverName, sourcePath),
	}}
}

func parseContinueConfig(obj map[string]any, sourcePath string) []types.McpServerConfig {
	var list []any
	if exp, ok := obj["experimental"].(map[string]any); ok {
		if arr, ok := exp["modelContextProtocolServers"].([]any); ok {
			list = arr
		}
	}
	if list == nil {
		if arr, ok := obj["mcpServers"].([]any); ok {
			list = arr
		}
	}
	var out []types.McpServerConfig
	for i, entry := range list {
		e, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name := "continue-mcp-" + itoa(i+1)
		if s, ok := e["name"].(string); ok {
			name = s
		}
		srv := types.McpServerConfig{
			Name:       name,
			SourcePath: sourcePath,
			Tools:      extractInlineTools(e, name, sourcePath),
		}
		if c, ok := e["command"].(string); ok {
			srv.Command = c
		}
		if args, ok := e["args"].([]any); ok {
			for _, a := range args {
				if s, ok := a.(string); ok {
					srv.Args = append(srv.Args, s)
				}
			}
		}
		out = append(out, srv)
	}
	return out
}

func extractInlineTools(serverObj map[string]any, serverName, sourcePath string) []types.ToolDescriptor {
	if t, ok := serverObj["tools"]; ok {
		return extractToolsArray(t, serverName, sourcePath)
	}
	return nil
}

func extractToolsArray(toolsRaw any, serverName, sourcePath string) []types.ToolDescriptor {
	switch t := toolsRaw.(type) {
	case []any:
		var out []types.ToolDescriptor
		for _, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if name == "" {
				continue
			}
			td := types.ToolDescriptor{
				Name:       name,
				ServerName: serverName,
				SourcePath: sourcePath,
			}
			if d, ok := m["description"].(string); ok {
				td.Description = d
			}
			if s, ok := m["inputSchema"]; ok {
				td.InputSchema = s
			} else if s, ok := m["parameters"]; ok {
				td.InputSchema = s
			} else if s, ok := m["schema"]; ok {
				td.InputSchema = s
			}
			out = append(out, td)
		}
		return out
	case map[string]any:
		// map form or wrapper with "tools"
		if inner, ok := t["tools"]; ok {
			return extractToolsArray(inner, serverName, sourcePath)
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []types.ToolDescriptor
		for _, name := range keys {
			def, ok := t[name].(map[string]any)
			if !ok {
				continue
			}
			td := types.ToolDescriptor{
				Name:       name,
				ServerName: serverName,
				SourcePath: sourcePath,
			}
			if d, ok := def["description"].(string); ok {
				td.Description = d
			}
			if s, ok := def["inputSchema"]; ok {
				td.InputSchema = s
			} else if s, ok := def["parameters"]; ok {
				td.InputSchema = s
			} else if s, ok := def["schema"]; ok {
				td.InputSchema = s
			}
			out = append(out, td)
		}
		return out
	default:
		return nil
	}
}

func firstMap(obj map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := obj[k].(map[string]any); ok {
			return v
		}
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
