package risk

import (
	"encoding/json"
	"regexp"
	"strings"
)

type Category string

const (
	Write   Category = "write"
	Exec    Category = "exec"
	Network Category = "network"
	Read    Category = "read"
	Unknown Category = "unknown"
)

type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

type Hint struct {
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
}

var (
	writeName   = regexp.MustCompile(`(?i)\b(write|create|update|delete|remove|patch|put|upload|edit|modify|append|truncate|mkdir|rm|mv|rename|save|set_|apply_)\b`)
	execName    = regexp.MustCompile(`(?i)\b(exec|shell|bash|zsh|cmd|run_command|run_terminal|spawn|subprocess|eval|system|popen|powershell)\b`)
	networkName = regexp.MustCompile(`(?i)\b(http|fetch|request|curl|wget|api|webhook|post|get_url|download|upload|browser|navigate|socket)\b`)
	readName    = regexp.MustCompile(`(?i)\b(read|list|get|search|find|scan|query|cat|head|tail|stat|glob|ls)\b`)

	writeDesc   = regexp.MustCompile(`(?i)\b(write|creat(e|ing)|delet(e|ing)|modif(y|ying)|overwrit|persist|save to disk|filesystem write)\b`)
	execDesc    = regexp.MustCompile(`(?i)\b(execut(e|ion)|shell command|run (a )?command|spawn a process|arbitrary code|os\.system)\b`)
	networkDesc = regexp.MustCompile(`(?i)\b(http(s)? request|network|fetch (from|url)|call (an )?api|send (a )?request|outbound)\b`)

	unconstrained = regexp.MustCompile(`(?i)\b(any path|arbitrary path|absolute path|without restriction|unrestricted|full filesystem|all files)\b`)
)

// Assess returns heuristic risk labels. Triage only; not a safety verdict.
func Assess(name, description string, inputSchema any) []Hint {
	var hints []Hint
	blob := name + " " + description

	if execName.MatchString(name) || execDesc.MatchString(description) {
		hints = append(hints, Hint{Category: Exec, Severity: Critical, Reason: "Name or description suggests shell/process execution"})
	}
	if writeName.MatchString(name) || writeDesc.MatchString(description) {
		hints = append(hints, Hint{Category: Write, Severity: High, Reason: "Name or description suggests filesystem or state mutation"})
	}
	if networkName.MatchString(name) || networkDesc.MatchString(description) {
		hints = append(hints, Hint{Category: Network, Severity: Medium, Reason: "Name or description suggests outbound network access"})
	}
	if len(hints) == 0 && readName.MatchString(name) {
		hints = append(hints, Hint{Category: Read, Severity: Low, Reason: "Looks primarily read-oriented"})
	}
	if unconstrained.MatchString(blob) {
		hints = append(hints, Hint{Category: Write, Severity: Critical, Reason: "Description claims unconstrained path access"})
	}
	hints = append(hints, schemaHints(inputSchema)...)

	if len(hints) == 0 {
		hints = append(hints, Hint{Category: Unknown, Severity: Low, Reason: "No strong write/exec/network signals from name or description"})
	}
	return dedupe(hints)
}

func schemaHints(schema any) []Hint {
	if schema == nil {
		return nil
	}
	b, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	text := strings.ToLower(string(b))
	var hints []Hint
	if strings.Contains(text, `"command"`) || strings.Contains(text, `"shell"`) || strings.Contains(text, `"argv"`) {
		hints = append(hints, Hint{Category: Exec, Severity: High, Reason: "Input schema accepts command/shell-like parameters"})
	}
	if strings.Contains(text, `"path"`) && (strings.Contains(text, `"write"`) || strings.Contains(text, `"content"`) || strings.Contains(text, `"contents"`)) {
		hints = append(hints, Hint{Category: Write, Severity: High, Reason: "Input schema pairs path with content/write fields"})
	}
	if strings.Contains(text, `"url"`) || strings.Contains(text, `"endpoint"`) {
		hints = append(hints, Hint{Category: Network, Severity: Medium, Reason: "Input schema accepts URL/endpoint parameters"})
	}
	return hints
}

func dedupe(hints []Hint) []Hint {
	seen := map[string]struct{}{}
	out := make([]Hint, 0, len(hints))
	for _, h := range hints {
		key := string(h.Category) + ":" + string(h.Severity) + ":" + h.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return out
}

func Categories(hints []Hint) []Category {
	seen := map[Category]struct{}{}
	var out []Category
	for _, h := range hints {
		if _, ok := seen[h.Category]; ok {
			continue
		}
		seen[h.Category] = struct{}{}
		out = append(out, h.Category)
	}
	return out
}
