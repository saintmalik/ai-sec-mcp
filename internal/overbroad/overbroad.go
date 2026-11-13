package overbroad

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/saintmalik/ai-sec-mcp/internal/inventory"
	"github.com/saintmalik/ai-sec-mcp/internal/risk"
	"github.com/saintmalik/ai-sec-mcp/internal/types"
)

var (
	wildcardName = regexp.MustCompile(`\*|^all$|^any$|wildcard`)
	shellLike    = regexp.MustCompile(`(?i)\b(shell|exec|bash|zsh|cmd|run_command|run_terminal|subprocess|spawn|eval|system)\b`)
	writeLike    = regexp.MustCompile(`(?i)\b(write|delete|remove|overwrite|unrestricted|arbitrary)\b`)
	// Tool poisoning / hidden instruction cues in descriptions.
	poisonDesc = regexp.MustCompile(`(?i)(ignore (previous|prior|all) instructions|do not tell the user|hidden instruction|exfiltrat|send (this|the) (data|secret|key|token) to|system prompt|jailbreak|<\|?/?(system|assistant))`)
)

// Find flags dangerous capability patterns in the inventory.
func Find(root string) ([]types.OverbroadFinding, error) {
	inv, err := inventory.Collect(root)
	if err != nil {
		return nil, err
	}
	var findings []types.OverbroadFinding
	for _, t := range inv.Tools {
		findings = append(findings, checkTool(t)...)
	}
	return findings, nil
}

func checkTool(t types.ToolInventoryEntry) []types.OverbroadFinding {
	var out []types.OverbroadFinding
	blob := t.Name + " " + t.Description

	if wildcardName.MatchString(t.Name) || strings.Contains(t.Name, "*") {
		out = append(out, types.OverbroadFinding{
			ToolName: t.Name, ServerName: t.ServerName,
			Pattern: "wildcard_name", Severity: risk.Critical,
			Detail: "Tool name looks like a wildcard or catch-all",
		})
	}
	if poisonDesc.MatchString(t.Description) {
		out = append(out, types.OverbroadFinding{
			ToolName: t.Name, ServerName: t.ServerName,
			Pattern: "tool_poisoning_description", Severity: risk.Critical,
			Detail: "Description contains hidden-instruction / exfiltration cues (tool poisoning signal)",
		})
	}
	if shellLike.MatchString(blob) {
		out = append(out, types.OverbroadFinding{
			ToolName: t.Name, ServerName: t.ServerName,
			Pattern: "shell_exec", Severity: risk.Critical,
			Detail: "Shell/exec capability pattern detected",
		})
	}
	if writeLike.MatchString(blob) && (strings.Contains(strings.ToLower(blob), "any path") ||
		strings.Contains(strings.ToLower(blob), "arbitrary") ||
		strings.Contains(strings.ToLower(blob), "unrestricted") ||
		strings.Contains(strings.ToLower(blob), "without restriction")) {
		out = append(out, types.OverbroadFinding{
			ToolName: t.Name, ServerName: t.ServerName,
			Pattern: "unconstrained_write", Severity: risk.Critical,
			Detail: "Write tool claims unconstrained path access",
		})
	}

	schemaText := ""
	if t.InputSchema != nil {
		if b, err := json.Marshal(t.InputSchema); err == nil {
			schemaText = strings.ToLower(string(b))
		}
	}
	if schemaText != "" {
		if strings.Contains(schemaText, `"additionalproperties":true`) || strings.Contains(schemaText, `"additionalproperties": true`) {
			out = append(out, types.OverbroadFinding{
				ToolName: t.Name, ServerName: t.ServerName,
				Pattern: "open_schema", Severity: risk.High,
				Detail: "Input schema allows additionalProperties: true",
			})
		}
		// path with no enum/pattern constraint paired with content
		if strings.Contains(schemaText, `"path"`) && strings.Contains(schemaText, `"content"`) &&
			!strings.Contains(schemaText, `"enum"`) && !strings.Contains(schemaText, `"pattern"`) {
			out = append(out, types.OverbroadFinding{
				ToolName: t.Name, ServerName: t.ServerName,
				Pattern: "unconstrained_path_write", Severity: risk.High,
				Detail: "Path+content schema without enum/pattern constraints",
			})
		}
		if strings.Contains(schemaText, `"command"`) || strings.Contains(schemaText, `"shell"`) {
			out = append(out, types.OverbroadFinding{
				ToolName: t.Name, ServerName: t.ServerName,
				Pattern: "command_parameter", Severity: risk.Critical,
				Detail: "Schema accepts a free-form command/shell parameter",
			})
		}
	}

	return out
}
