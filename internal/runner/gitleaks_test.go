package runner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// gitleaksRun runs the built-in plugin id over target with a fake engine
// and returns its result and the configuration file the tool would read.
func gitleaksRun(t *testing.T, id string, target string) (report.PluginResult, string) {
	t.Helper()
	var config string
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		if s.Env["GITLEAKS_CONFIG"] != sandbox.ConfigMountTOML || !strings.HasSuffix(s.ConfigFile, ".toml") {
			t.Errorf("spec: env %v, config file %q", s.Env, s.ConfigFile)
		}
		if _, ok := s.Env["GITLEAKS_CONFIG_TOML"]; ok {
			t.Error("GITLEAKS_CONFIG_TOML set")
		}
		b, err := os.ReadFile(s.ConfigFile)
		if err != nil {
			t.Fatal(err)
		}
		config = string(b)
		write(t, s.OutDir, id+".sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`)
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	o := opts(t)
	o.TargetDir = target
	r, err := Run(context.Background(), f, []*manifest.Manifest{builtin(t, id)}, o)
	if err != nil {
		t.Fatal(err)
	}
	return r.Plugins[0], config
}

// Both scans use the repository's .gitleaks.toml when there is one, else
// Gitleaks' default rules, and add SiegeKit's rules after them; the report
// says which (SK-1 and SK-2, ADR 0063).
func TestGitleaksConfig(t *testing.T) {
	supabase := "siegekit-supabase-secret-key, siegekit-supabase-publishable-key"
	for _, id := range []string{"gitleaks", "gitleaks-history"} {
		target := t.TempDir()
		if err := os.Mkdir(filepath.Join(target, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		m := builtin(t, id)
		rules := "SiegeKit's rules " + supabase
		if id == "gitleaks-history" {
			rules = "SiegeKit's rules env-file-committed, " + supabase
		}

		p, cfg := gitleaksRun(t, id, target)
		if p.Status != report.Ran || p.Input != "Gitleaks' default rules and "+rules || len(p.RepoSettings) != 0 {
			t.Errorf("%s without a repository config: %+v", id, p)
		}
		if cfg != gitleaksDefaults+"\n\n"+m.Run.GitleaksRules {
			t.Errorf("%s config without a repository config:\n%s", id, cfg)
		}

		own := "title = \"own\"\n[extend]\npath = \"/target/base.toml\"\n[[rules]]\nid = \"supabase-secret-key\"\nregex = '''sb_secret_[a-z]+'''\n"
		write(t, target, ".gitleaks.toml", own)
		p, cfg = gitleaksRun(t, id, target)
		if p.Status != report.Ran || p.Input != "the rules in the repository's .gitleaks.toml and "+rules || !slices.Contains(p.RepoSettings, ".gitleaks.toml") {
			t.Errorf("%s with a repository config: %+v", id, p)
		}
		if cfg != own+"\n\n"+m.Run.GitleaksRules {
			t.Errorf("%s config with a repository config:\n%s", id, cfg)
		}
	}
}

// A repository config SiegeKit cannot use as it is fails the check, saying
// why, instead of scanning without the repository's rules.
func TestGitleaksConfigRefused(t *testing.T) {
	big := "# " + strings.Repeat("x", maxGitleaksRepoConfig) + "\n"
	for name, c := range map[string]struct {
		setup func(t *testing.T, dir string)
		want  string
	}{
		"link": {func(t *testing.T, dir string) {
			write(t, dir, "real.toml", "title = \"x\"\n")
			if err := os.Symlink("real.toml", filepath.Join(dir, ".gitleaks.toml")); err != nil {
				t.Fatal(err)
			}
		}, "is a link"},
		"folder": {func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, ".gitleaks.toml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		"too large": {func(t *testing.T, dir string) { write(t, dir, ".gitleaks.toml", big) }, "larger than"},
		"not UTF-8": {func(t *testing.T, dir string) { write(t, dir, ".gitleaks.toml", "title = \"\xff\"\n") }, "not UTF-8 text"},
		"NUL":       {func(t *testing.T, dir string) { write(t, dir, ".gitleaks.toml", "title = \"\x00\"\n") }, "not UTF-8 text"},
		"same id": {func(t *testing.T, dir string) {
			write(t, dir, ".gitleaks.toml", "[[rules]]\nid = \"siegekit-supabase-secret-key\"\n")
		}, `rule with the id "siegekit-supabase-secret-key"`},
		"same id 'x'": {func(t *testing.T, dir string) {
			write(t, dir, ".gitleaks.toml", "[[rules]]\n  id='''siegekit-supabase-publishable-key'''\n")
		}, `"siegekit-supabase-publishable-key"`},
		"same id inline": {func(t *testing.T, dir string) {
			write(t, dir, ".gitleaks.toml", "rules = [{ \"id\" = \"siegekit-supabase-secret-key\" }]\n")
		}, `"siegekit-supabase-secret-key"`},
	} {
		dir := t.TempDir()
		c.setup(t, dir)
		f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
			t.Errorf("%s: the tool ran", name)
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}}
		o := opts(t)
		o.TargetDir = dir
		r, err := Run(context.Background(), f, []*manifest.Manifest{builtin(t, "gitleaks")}, o)
		if err != nil {
			t.Fatal(err)
		}
		if p := r.Plugins[0]; p.Status != report.Failed || !strings.Contains(p.Reason, c.want) {
			t.Errorf("%s: %+v, want %q", name, p, c.want)
		}
	}
	// An id that only starts like SiegeKit's is another rule.
	dir := t.TempDir()
	write(t, dir, ".gitleaks.toml", "[[rules]]\nid = \"siegekit-supabase-secret-key-old\"\n")
	if p, _ := gitleaksRun(t, "gitleaks", dir); p.Status != report.Ran {
		t.Errorf("longer id: %+v", p)
	}
}
