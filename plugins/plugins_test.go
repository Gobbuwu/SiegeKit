package plugins

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
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

func TestLoadRefusesBrokenManifests(t *testing.T) {
	good, err := files.ReadFile("gitleaks/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"invalid":         {fstest.MapFS{"x/plugin.json": {Data: []byte(`{}`)}}, "x/plugin.json"},
		"wrong directory": {fstest.MapFS{"other/plugin.json": {Data: good}}, `does not match directory "other"`},
		"unreadable":      {fstest.MapFS{"gitleaks/plugin.json": {Mode: fs.ModeDir}}, "gitleaks/plugin.json"},
	} {
		if _, err := load(tc.fsys); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	ms, err := load(fstest.MapFS{"gitleaks/plugin.json": {Data: good}})
	if err != nil || len(ms) != 1 || ms[0].ID != "gitleaks" {
		t.Errorf("good manifest: %v %v", ms, err)
	}
}
