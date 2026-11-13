package inventory

import (
	"sort"

	"github.com/saintmalik/ai-sec-mcp/internal/hashutil"
	"github.com/saintmalik/ai-sec-mcp/internal/risk"
	"github.com/saintmalik/ai-sec-mcp/internal/scanner"
	"github.com/saintmalik/ai-sec-mcp/internal/types"
)

type Result struct {
	Configs []types.DiscoveredConfig  `json:"configs"`
	Servers []types.McpServerConfig   `json:"servers"`
	Tools   []types.ToolInventoryEntry `json:"tools"`
}

// Collect scans root and builds a tool inventory with risk hints and fingerprints.
func Collect(root string) (*Result, error) {
	configs, err := scanner.ScanRepo(root)
	if err != nil {
		return nil, err
	}

	var servers []types.McpServerConfig
	for _, cfg := range configs {
		parsed, err := scanner.ParseServersFromConfig(cfg)
		if err != nil {
			continue
		}
		servers = append(servers, parsed...)
	}

	manifestTools, _ := scanner.LoadNearbyManifests(root, servers)

	toolMap := map[string]types.ToolDescriptor{}
	keyOf := func(server, name string) string { return server + "::" + name }

	for _, srv := range servers {
		for _, t := range srv.Tools {
			t.ServerName = srv.Name
			if t.SourcePath == "" {
				t.SourcePath = srv.SourcePath
			}
			toolMap[keyOf(t.ServerName, t.Name)] = t
		}
	}
	for _, t := range manifestTools {
		if t.ServerName == "" {
			t.ServerName = "manifest"
		}
		toolMap[keyOf(t.ServerName, t.Name)] = t
	}

	tools := make([]types.ToolInventoryEntry, 0, len(toolMap))
	for _, t := range toolMap {
		hints := risk.Assess(t.Name, t.Description, t.InputSchema)
		tools = append(tools, types.ToolInventoryEntry{
			ToolDescriptor: t,
			RiskHints:      hints,
			Fingerprint:    hashutil.ToolFingerprint(t.Name, t.Description, t.InputSchema),
		})
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].ServerName == tools[j].ServerName {
			return tools[i].Name < tools[j].Name
		}
		return tools[i].ServerName < tools[j].ServerName
	})

	return &Result{
		Configs: configs,
		Servers: servers,
		Tools:   tools,
	}, nil
}
