package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/saintmalik/ai-sec-mcp/internal/hashutil"
	"github.com/saintmalik/ai-sec-mcp/internal/inventory"
	"github.com/saintmalik/ai-sec-mcp/internal/risk"
	"github.com/saintmalik/ai-sec-mcp/internal/sandbox"
	"github.com/saintmalik/ai-sec-mcp/internal/types"
)

const DefaultName = "mcp-lockfile.json"

// Build creates a lockfile from the current inventory.
func Build(root string) (*types.ToolLockfile, error) {
	inv, err := inventory.Collect(root)
	if err != nil {
		return nil, err
	}
	tools := make([]types.LockfileTool, 0, len(inv.Tools))
	for _, t := range inv.Tools {
		tools = append(tools, types.LockfileTool{
			Name:            t.Name,
			ServerName:      t.ServerName,
			DescriptionHash: hashutil.HashDescription(t.Description),
			SchemaHash:      hashutil.HashSchema(t.InputSchema),
			Fingerprint:     t.Fingerprint,
			RiskCategories:  risk.Categories(t.RiskHints),
		})
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].ServerName == tools[j].ServerName {
			return tools[i].Name < tools[j].Name
		}
		return tools[i].ServerName < tools[j].ServerName
	})
	return &types.ToolLockfile{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SourceRoots: []string{root},
		Tools:       tools,
		Digest:      digestOf(tools),
	}, nil
}

// Write builds and writes the lockfile to path (or default under root).
// Relative outPath is confined under root. Absolute outPath is allowed for CI temp artifacts.
// Empty means <root>/mcp-lockfile.json.
func Write(root, outPath string) (*types.ToolLockfile, string, error) {
	rootAbs, err := sandbox.ResolveRoot(root)
	if err != nil {
		return nil, "", err
	}
	lf, err := Build(rootAbs)
	if err != nil {
		return nil, "", err
	}
	if outPath == "" {
		outPath = filepath.Join(rootAbs, DefaultName)
	} else if filepath.IsAbs(outPath) {
		outPath = filepath.Clean(outPath)
	} else {
		confined, err := sandbox.ConfinePath(rootAbs, outPath)
		if err != nil {
			return nil, "", fmt.Errorf("lockfile out path: %w", err)
		}
		outPath = confined
	}
	b, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return nil, "", err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		return nil, "", err
	}
	return lf, outPath, nil
}

// Load reads a lockfile from disk.
func Load(path string) (*types.ToolLockfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf types.ToolLockfile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, err
	}
	return &lf, nil
}

// FindDefault looks for a lockfile in common locations under root.
func FindDefault(root string) (string, error) {
	candidates := []string{
		filepath.Join(root, DefaultName),
		filepath.Join(root, ".ai-sec", DefaultName),
		filepath.Join(root, "ai-sec-lockfile.json"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no lockfile found under %s (tried %s)", root, strings.Join(candidates, ", "))
}

// Diff compares baseline lockfile against current inventory. Fail-closed: any drift => !OK.
func Diff(root, baselinePath string) (*types.DiffResult, error) {
	if baselinePath == "" {
		p, err := FindDefault(root)
		if err != nil {
			return nil, err
		}
		baselinePath = p
	}
	baseline, err := Load(baselinePath)
	if err != nil {
		return nil, err
	}
	current, err := Build(root)
	if err != nil {
		return nil, err
	}

	baseMap := map[string]types.LockfileTool{}
	for _, t := range baseline.Tools {
		baseMap[key(t.ServerName, t.Name)] = t
	}
	curMap := map[string]types.LockfileTool{}
	for _, t := range current.Tools {
		curMap[key(t.ServerName, t.Name)] = t
	}

	var drifts []types.DriftEntry
	for k, bt := range baseMap {
		ct, ok := curMap[k]
		if !ok {
			drifts = append(drifts, types.DriftEntry{
				Kind:       types.DriftRemoved,
				Name:       bt.Name,
				ServerName: bt.ServerName,
				Detail:     "Tool present in lockfile but missing from current inventory",
			})
			continue
		}
		if bt.DescriptionHash != ct.DescriptionHash {
			drifts = append(drifts, types.DriftEntry{
				Kind:       types.DriftDescriptionChanged,
				Name:       bt.Name,
				ServerName: bt.ServerName,
				Detail:     fmt.Sprintf("description hash %s -> %s", short(bt.DescriptionHash), short(ct.DescriptionHash)),
			})
		}
		if bt.SchemaHash != ct.SchemaHash {
			drifts = append(drifts, types.DriftEntry{
				Kind:       types.DriftSchemaChanged,
				Name:       bt.Name,
				ServerName: bt.ServerName,
				Detail:     fmt.Sprintf("schema hash %s -> %s", short(bt.SchemaHash), short(ct.SchemaHash)),
			})
		}
		if bt.Fingerprint != ct.Fingerprint && bt.DescriptionHash == ct.DescriptionHash && bt.SchemaHash == ct.SchemaHash {
			drifts = append(drifts, types.DriftEntry{
				Kind:       types.DriftFingerprintChanged,
				Name:       bt.Name,
				ServerName: bt.ServerName,
				Detail:     "fingerprint changed without description/schema hash change",
			})
		}
	}
	for k, ct := range curMap {
		if _, ok := baseMap[k]; !ok {
			drifts = append(drifts, types.DriftEntry{
				Kind:       types.DriftAdded,
				Name:       ct.Name,
				ServerName: ct.ServerName,
				Detail:     "New tool not present in lockfile",
			})
		}
	}

	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].ServerName == drifts[j].ServerName {
			if drifts[i].Name == drifts[j].Name {
				return drifts[i].Kind < drifts[j].Kind
			}
			return drifts[i].Name < drifts[j].Name
		}
		return drifts[i].ServerName < drifts[j].ServerName
	})

	return &types.DiffResult{
		OK:             len(drifts) == 0,
		BaselineDigest: baseline.Digest,
		CurrentDigest:  current.Digest,
		Drifts:         drifts,
	}, nil
}

func digestOf(tools []types.LockfileTool) string {
	parts := make([]string, 0, len(tools))
	for _, t := range tools {
		parts = append(parts, t.Fingerprint)
	}
	sort.Strings(parts)
	return hashutil.SHA256(strings.Join(parts, "\n"))
}

func key(server, name string) string { return server + "::" + name }

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
