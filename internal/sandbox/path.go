package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const MaxScanDepth = 6

// ResolveRoot cleans and absolutizes a user-supplied workspace root.
func ResolveRoot(path string) (string, error) {
	if path == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		path = wd
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace root not accessible: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("workspace root is not a directory: %s", abs)
	}
	return abs, nil
}

// WithinRoot returns true if candidate resolves inside root (no symlink escape check beyond EvalSymlinks when possible).
func WithinRoot(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rootAbs = filepath.Clean(rootAbs)
	candAbs = filepath.Clean(candAbs)

	// Best-effort symlink resolution; if EvalSymlinks fails, fall back to cleaned paths.
	if r, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = r
	}
	if c, err := filepath.EvalSymlinks(candAbs); err == nil {
		candAbs = c
	} else {
		// If candidate does not exist yet, evaluate parent.
		if p, err := filepath.EvalSymlinks(filepath.Dir(candAbs)); err == nil {
			candAbs = filepath.Join(p, filepath.Base(candAbs))
		}
	}

	rel, err := filepath.Rel(rootAbs, candAbs)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

// ConfinePath joins root with a relative path and rejects escapes.
func ConfinePath(root, relOrAbs string) (string, error) {
	rootAbs, err := ResolveRoot(root)
	if err != nil {
		return "", err
	}
	var candidate string
	if filepath.IsAbs(relOrAbs) {
		candidate = filepath.Clean(relOrAbs)
	} else {
		candidate = filepath.Join(rootAbs, filepath.Clean(relOrAbs))
	}
	if !WithinRoot(rootAbs, candidate) {
		return "", fmt.Errorf("path escapes workspace root: %s", relOrAbs)
	}
	return candidate, nil
}
