package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCountMarker(t *testing.T) {
	root := t.TempDir()
	for p, body := range map[string]string{
		"a.py":                  "k = 1  # gitleaks:allow\nx = 2\n# gitleaks:allow twice gitleaks:allow\n",
		"sub/b.js":              "// gitleaks:allow\n",
		"node_modules/c.js":     "// gitleaks:allow\n", // dependency directories are skipped
		"clean.txt":             "nothing here\n",
		".git/hooks/pre-commit": "gitleaks:allow\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "a.py"), filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}
	n, err := CountMarker(context.Background(), root, "gitleaks:allow")
	if err != nil || n != 3 {
		t.Errorf("CountMarker = %d, %v; want 3 lines", n, err)
	}
	if n, err := CountMarker(context.Background(), root, ""); n != 0 || err != nil {
		t.Errorf("empty marker: %d, %v", n, err)
	}
}
