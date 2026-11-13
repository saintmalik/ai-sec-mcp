package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/saintmalik/ai-sec-mcp/internal/inventory"
	"github.com/saintmalik/ai-sec-mcp/internal/lockfile"
	"github.com/saintmalik/ai-sec-mcp/internal/overbroad"
	"github.com/saintmalik/ai-sec-mcp/internal/risk"
	"github.com/saintmalik/ai-sec-mcp/internal/types"
)

// Build produces a capability report suitable for CI / PR comments.
func Build(root, lockPath string) (*types.CapabilityReport, error) {
	inv, err := inventory.Collect(root)
	if err != nil {
		return nil, err
	}
	findings, err := overbroad.Find(root)
	if err != nil {
		return nil, err
	}

	var high []types.HighRiskTool
	for _, t := range inv.Tools {
		var severe []risk.Hint
		for _, h := range t.RiskHints {
			if h.Severity == risk.High || h.Severity == risk.Critical {
				severe = append(severe, h)
			}
		}
		if len(severe) > 0 {
			high = append(high, types.HighRiskTool{
				Name: t.Name, ServerName: t.ServerName, Hints: severe,
			})
		}
	}

	rep := &types.CapabilityReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Root:          root,
		ConfigsFound:  len(inv.Configs),
		Servers:       len(inv.Servers),
		Tools:         len(inv.Tools),
		Overbroad:     findings,
		HighRiskTools: high,
		Inventory:     inv.Tools,
	}

	path := lockPath
	if path == "" {
		if p, err := lockfile.FindDefault(root); err == nil {
			path = p
		}
	}
	if path != "" {
		diff, err := lockfile.Diff(root, path)
		part := &types.LockfileReportPart{Path: &path, Drifts: nil}
		if err != nil {
			ok := false
			part.OK = &ok
			part.Drifts = []types.DriftEntry{{
				Kind:   types.DriftFingerprintChanged,
				Name:   "(lockfile)",
				Detail: err.Error(),
			}}
		} else {
			ok := diff.OK
			part.OK = &ok
			part.Drifts = diff.Drifts
		}
		rep.Lockfile = part
	} else {
		rep.Lockfile = &types.LockfileReportPart{Path: nil, OK: nil, Drifts: nil}
	}

	return rep, nil
}

func ToJSON(rep *types.CapabilityReport) ([]byte, error) {
	return json.MarshalIndent(rep, "", "  ")
}

func ToMarkdown(rep *types.CapabilityReport) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "## ai-sec-mcp capability report\n\n")
	fmt.Fprintf(&b, "- **Root:** `%s`\n", rep.Root)
	fmt.Fprintf(&b, "- **Generated:** %s\n", rep.GeneratedAt)
	fmt.Fprintf(&b, "- **Configs:** %d | **Servers:** %d | **Tools:** %d\n", rep.ConfigsFound, rep.Servers, rep.Tools)

	if rep.Lockfile != nil {
		fmt.Fprintf(&b, "\n### Lockfile\n\n")
		if rep.Lockfile.Path == nil {
			fmt.Fprintf(&b, "_No lockfile found. Run `ai-sec-mcp lock` to create one._\n")
		} else {
			fmt.Fprintf(&b, "- **Path:** `%s`\n", *rep.Lockfile.Path)
			if rep.Lockfile.OK != nil && *rep.Lockfile.OK {
				fmt.Fprintf(&b, "- **Status:** pass (no drift)\n")
			} else if rep.Lockfile.OK != nil {
				fmt.Fprintf(&b, "- **Status:** **FAIL** (%d drift(s))\n", len(rep.Lockfile.Drifts))
				for _, d := range rep.Lockfile.Drifts {
					fmt.Fprintf(&b, "  - `%s/%s` (%s): %s\n", d.ServerName, d.Name, d.Kind, d.Detail)
				}
			}
		}
	}

	fmt.Fprintf(&b, "\n### Overbroad findings\n\n")
	if len(rep.Overbroad) == 0 {
		fmt.Fprintf(&b, "_None flagged._\n")
	} else {
		for _, f := range rep.Overbroad {
			fmt.Fprintf(&b, "- **[%s]** `%s/%s` (%s): %s\n", strings.ToUpper(string(f.Severity)), f.ServerName, f.ToolName, f.Pattern, f.Detail)
		}
	}

	fmt.Fprintf(&b, "\n### High / critical risk tools\n\n")
	if len(rep.HighRiskTools) == 0 {
		fmt.Fprintf(&b, "_None flagged._\n")
	} else {
		for _, t := range rep.HighRiskTools {
			reasons := make([]string, 0, len(t.Hints))
			for _, h := range t.Hints {
				reasons = append(reasons, fmt.Sprintf("%s/%s", h.Severity, h.Category))
			}
			fmt.Fprintf(&b, "- `%s/%s`: %s\n", t.ServerName, t.Name, strings.Join(reasons, ", "))
		}
	}

	fmt.Fprintf(&b, "\n---\n_Local capability auditor. Heuristics only; review drifts before approving._\n")
	return b.String()
}
