package redact_test

import (
	"strings"
	"testing"

	"github.com/saintmalik/ai-sec-mcp/internal/redact"
)

func TestRedactsBearerAndEnv(t *testing.T) {
	s := redact.String(`Authorization: Bearer test-token-not-real`)
	if strings.Contains(strings.ToLower(s), "test-token-not-real") {
		t.Fatalf("token not redacted: %s", s)
	}
	env := redact.EnvMap(map[string]string{
		"OPENAI_API_KEY": "REDACTED_TEST_PLACEHOLDER_ONLY",
		"PATH":           "/usr/bin",
	})
	if env["OPENAI_API_KEY"] == "REDACTED_TEST_PLACEHOLDER_ONLY" {
		t.Fatal("api key env not redacted")
	}
	if env["PATH"] != "/usr/bin" {
		t.Fatal("non-secret env should pass through")
	}
}
