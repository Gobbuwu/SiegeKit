package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

func f(rule, plugin string) findings.Finding {
	x := findings.Finding{RuleID: rule, Location: findings.Location{URI: "a.go", StartLine: 1}, Sources: []findings.Source{{Plugin: plugin, RuleID: rule}}}
	x.ComputeFingerprint()
	return x
}

func TestSaveLoadList(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "runs")}
	r := &report.Run{Target: "./My App!", Started: time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC), Findings: []findings.Finding{f("r1", "p")}}
	id, err := s.Save(r, r.Target)
	if err != nil {
		t.Fatal(err)
	}
	if id != "20261118T010203Z-my-app" {
		t.Fatalf("id = %q", id)
	}
	if _, err := s.Save(r, r.Target); err == nil {
		t.Fatal("expected refusal to overwrite an existing run")
	}
	got, err := s.Load(id)
	if err != nil || len(got.Findings) != 1 {
		t.Fatalf("load: %v %+v", err, got)
	}
	ids, err := s.List()
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("list: %v %v", ids, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(s.Dir, id+".json"))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("run file mode %v, want 0600", st.Mode().Perm())
		}
	}
	for _, bad := range []string{"../etc/passwd", "x", "20261118T010203Z-../../a"} {
		if _, err := s.Load(bad); err == nil {
			t.Errorf("Load(%q) should be rejected", bad)
		}
	}
}

func TestCompareDoesNotCallUncheckedFindingsFixed(t *testing.T) {
	prev := &report.Run{Findings: []findings.Finding{f("a", "semgrep"), f("b", "gitleaks"), f("c", "semgrep")}}
	cur := &report.Run{
		Plugins:  []report.PluginResult{{ID: "semgrep", Status: report.Ran}, {ID: "gitleaks", Status: report.Failed}},
		Findings: []findings.Finding{f("c", "semgrep"), f("d", "semgrep")},
	}
	d := Compare(prev, cur)
	if len(d.Fixed) != 1 || d.Fixed[0].RuleID != "a" {
		t.Errorf("fixed = %+v", d.Fixed)
	}
	if len(d.New) != 1 || d.New[0].RuleID != "d" {
		t.Errorf("new = %+v", d.New)
	}
	if len(d.Still) != 2 {
		t.Errorf("still = %+v (b must stay because gitleaks failed)", d.Still)
	}
}

func TestListMissingDir(t *testing.T) {
	ids, err := (&Store{Dir: filepath.Join(t.TempDir(), "none")}).List()
	if err != nil || ids != nil {
		t.Fatalf("got %v %v", ids, err)
	}
}
