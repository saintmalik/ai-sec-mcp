package redact

import (
	"regexp"
	"strings"
)

// Patterns that should never appear in tool results or stderr logs.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|password|passwd|token|authorization|bearer|private[_-]?key)\s*[=:]\s*["']?[^\s"',}]{8,}`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-._~+/]+=*`),
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`(?i)github_pat_[a-zA-Z0-9_]{20,}`),
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`(?i)xox[baprs]-[a-zA-Z0-9-]{10,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

const placeholder = "[REDACTED]"

// String redacts likely secrets from text returned to the model or logs.
func String(s string) string {
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, placeholder)
	}
	return out
}

// EnvMap returns a copy of env with values for sensitive keys replaced.
func EnvMap(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		if sensitiveKey(k) {
			out[k] = placeholder
			continue
		}
		out[k] = String(v)
	}
	return out
}

func sensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, needle := range []string{"key", "secret", "token", "password", "passwd", "credential", "auth", "api"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}
