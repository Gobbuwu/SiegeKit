package plugins

import (
	"strings"
	"testing"
)

func TestBuiltin(t *testing.T) {
	ms, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bandit", "checkov", "gitleaks", "gitleaks-history", "gosec", "trivy"}
	if len(ms) != len(want) {
		t.Fatalf("got %d plugins, want %v", len(ms), want)
	}
	for i, m := range ms {
		if m.ID != want[i] {
			t.Errorf("plugin %d is %q, want %q", i, m.ID, want[i])
		}
		// Built-in plugins must be real pins, not test placeholders.
		for _, a := range m.Tool.Artifacts {
			if strings.Contains(a.SHA256, strings.Repeat("0", 16)) || strings.Contains(a.Ref, ".invalid") {
				t.Errorf("%s: placeholder artifact %s", m.ID, a.Ref)
			}
		}
		if *m.Destructive || m.Mode != "passive" || m.Network != "none" {
			t.Errorf("%s: M1 built-ins must be passive, non-destructive and offline", m.ID)
		}
	}
}
