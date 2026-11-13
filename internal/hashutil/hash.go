package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

func SHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func HashDescription(description string) string {
	return SHA256(strings.TrimSpace(description))
}

func HashSchema(schema any) string {
	if schema == nil {
		return SHA256("")
	}
	b, err := StableJSON(schema)
	if err != nil {
		return SHA256("")
	}
	return SHA256(string(b))
}

func ToolFingerprint(name, description string, schema any) string {
	return SHA256(name + "\n" + HashDescription(description) + "\n" + HashSchema(schema))
}

func StableJSON(v any) ([]byte, error) {
	normalized, err := normalize(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func normalize(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return sortKeys(generic), nil
}

func sortKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortKeys(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = sortKeys(item)
		}
		return out
	default:
		return t
	}
}
