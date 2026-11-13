package lockfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saintmalik/ai-sec-mcp/internal/lockfile"
)

func TestDiffDetectsAddedWriteTool(t *testing.T) {
	root := repoRoot(t)
	clean := filepath.Join(root, "fixtures", "clean")
	bad := filepath.Join(root, "fixtures", "bad-new-write-tool")

	tmp := t.TempDir()
	lockPath := filepath.Join(tmp, "mcp-lockfile.json")
	if _, _, err := lockfile.Write(clean, lockPath); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	ok, err := lockfile.Diff(clean, lockPath)
	if err != nil {
		t.Fatalf("diff clean: %v", err)
	}
	if !ok.OK {
		t.Fatalf("clean should match lockfile, drifts=%v", ok.Drifts)
	}

	badDiff, err := lockfile.Diff(bad, lockPath)
	if err != nil {
		t.Fatalf("diff bad: %v", err)
	}
	if badDiff.OK {
		t.Fatal("expected fail-closed on new write tool")
	}
	found := false
	for _, d := range badDiff.Drifts {
		if d.Kind == "added" && d.Name == "write_file" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected added write_file drift, got %#v", badDiff.Drifts)
	}
}

func TestDiffDetectsSchemaDrift(t *testing.T) {
	root := repoRoot(t)
	clean := filepath.Join(root, "fixtures", "clean")
	bad := filepath.Join(root, "fixtures", "bad-schema-drift")

	tmp := t.TempDir()
	lockPath := filepath.Join(tmp, "mcp-lockfile.json")
	if _, _, err := lockfile.Write(clean, lockPath); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	diff, err := lockfile.Diff(bad, lockPath)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.OK {
		t.Fatal("expected schema/description drift to fail")
	}
	hasDescOrSchema := false
	for _, d := range diff.Drifts {
		if d.Kind == "description_changed" || d.Kind == "schema_changed" {
			hasDescOrSchema = true
		}
	}
	if !hasDescOrSchema {
		t.Fatalf("expected description/schema drift, got %#v", diff.Drifts)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/lockfile -> repo root
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
