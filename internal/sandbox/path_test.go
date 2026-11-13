package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saintmalik/ai-sec-mcp/internal/sandbox"
)

func TestWithinRootRejectsEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if !sandbox.WithinRoot(root, inside) {
		t.Fatal("expected inside path to be allowed")
	}
	outside := filepath.Join(root, "..", "nope")
	if sandbox.WithinRoot(root, outside) {
		t.Fatal("expected path escape to be rejected")
	}
}

func TestConfinePath(t *testing.T) {
	root := t.TempDir()
	p, err := sandbox.ConfinePath(root, "mcp-lockfile.json")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != root {
		t.Fatalf("got %s", p)
	}
	if _, err := sandbox.ConfinePath(root, "../outside.json"); err == nil {
		t.Fatal("expected escape to fail")
	}
}
