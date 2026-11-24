package store

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
	// The same second again: never overwritten, saved with a suffix.
	for n := 2; n <= 9; n++ {
		if id2, err := s.Save(r, r.Target); err != nil || id2 != id+"-"+strconv.Itoa(n) {
			t.Fatalf("second save: %q %v", id2, err)
		}
	}
	if _, err := s.Save(r, r.Target); err == nil {
		t.Fatal("expected an error after nine runs in one second")
	}
	got, err := s.Load(id)
	if err != nil || len(got.Findings) != 1 {
		t.Fatalf("load: %v %+v", err, got)
	}
	ids, err := s.List()
	if err != nil || len(ids) != 9 || ids[0] != id || ids[8] != id+"-9" {
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

func TestComparison(t *testing.T) {
	prev := &report.Run{SiegeKitVersion: "0.1", Started: time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC),
		Findings: []findings.Finding{f("a", "semgrep"), f("b", "gitleaks"), f("c", "semgrep")}}
	cur := &report.Run{
		SiegeKitVersion: "0.1",
		Plugins:         []report.PluginResult{{ID: "semgrep", Status: report.Ran}, {ID: "gitleaks", Status: report.Failed}},
		Findings:        []findings.Finding{f("c", "semgrep"), f("d", "semgrep")},
	}
	c := Comparison("id1", prev, cur)
	if c.PreviousRun != "id1" || len(c.New) != 1 || c.New[0] != f("d", "semgrep").Fingerprint ||
		len(c.Fixed) != 1 || c.Fixed[0].RuleID != "a" || len(c.NotRechecked) != 1 || c.NotRechecked[0].RuleID != "b" || c.StillPresent != 1 {
		t.Fatalf("comparison %+v", c)
	}
	if s := c.Summary(); s != "Since the last scan of this target (2026-11-18 01:02 UTC): 1 new, 1 fixed, 1 still present, 1 not checked again because their check could not run or did not complete." || len(c.NotRun) != 0 {
		t.Errorf("summary %q, not run %d", s, len(c.NotRun))
	}
	if c.VersionNote("0.1") != "" || !strings.Contains(c.VersionNote("0.2"), "SiegeKit 0.1, this one 0.2") {
		t.Error("version note")
	}
	// Empty lists, never null, in report.json.
	e := Comparison("id2", &report.Run{}, &report.Run{})
	if e.New == nil || e.Fixed == nil || e.NotRechecked == nil || e.NotRun == nil {
		t.Errorf("nil list in %+v", e)
	}
}

// A finding whose checks were all left out of this run, by --only or --skip
// (not in the run at all) or by --profile (skipped with that cause), is "not
// run", not "not checked again" (SK-9, ADR 0063). One check that could not
// run or did not complete makes it "not checked again".
func TestComparisonLeftOut(t *testing.T) {
	both := f("both", "gitleaks")
	both.Sources = append(both.Sources, findings.Source{Plugin: "trivy", RuleID: "both"})
	prev := &report.Run{Started: time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC),
		Findings: []findings.Finding{f("only", "gitleaks"), f("profile", "zap-active"), f("missing", "trivy"), both}}
	for name, tc := range map[string]struct {
		plugins      []report.PluginResult
		notRun       []string
		notRechecked []string
	}{
		"left out by --only, --skip and --profile": {
			plugins: []report.PluginResult{{ID: "zap-active", Status: report.Skipped, Cause: report.CauseProfile}},
			notRun:  []string{"only", "profile", "missing", "both"},
		},
		"a dependency is missing": {
			plugins:      []report.PluginResult{{ID: "trivy", Status: report.Skipped, Cause: report.CauseMissingDependency}},
			notRun:       []string{"only", "profile"},
			notRechecked: []string{"missing", "both"},
		},
		"timed out": {
			plugins:      []report.PluginResult{{ID: "gitleaks", Status: report.TimedOut}, {ID: "zap-active", Status: report.Skipped, Cause: report.CauseProfile}},
			notRun:       []string{"profile", "missing"},
			notRechecked: []string{"only", "both"},
		},
	} {
		c := Comparison("id", prev, &report.Run{Plugins: tc.plugins})
		var notRun, notRechecked []string
		for _, x := range c.NotRun {
			notRun = append(notRun, x.RuleID)
		}
		for _, x := range c.NotRechecked {
			notRechecked = append(notRechecked, x.RuleID)
		}
		slices.Sort(notRun)
		slices.Sort(notRechecked)
		slices.Sort(tc.notRun)
		slices.Sort(tc.notRechecked)
		if !slices.Equal(notRun, tc.notRun) || !slices.Equal(notRechecked, tc.notRechecked) || len(c.Fixed) != 0 {
			t.Errorf("%s: not run %v, not checked again %v, fixed %d", name, notRun, notRechecked, len(c.Fixed))
		}
	}
	c := Comparison("id", prev, &report.Run{})
	if s := c.Summary(); !strings.HasSuffix(s, ": 0 new, 0 fixed, 0 still present, 4 not run this time because their check was left out (--only, --skip or --profile).") {
		t.Errorf("summary %q", s)
	}
	// They stay open: the next run that checks them reports them as still
	// present or fixed, never as new.
	run2 := &report.Run{Comparison: c}
	if c2 := Comparison("id2", run2, &report.Run{Plugins: []report.PluginResult{{ID: "gitleaks", Status: report.Ran}}, Findings: []findings.Finding{both}}); len(c2.New) != 0 || c2.StillPresent != 1 || len(c2.Fixed) != 1 || len(c2.NotRun) != 2 {
		t.Errorf("next run: %+v", c2)
	}
}

func TestLatest(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "runs")}
	if id, r, err := s.Latest("/a"); id != "" || r != nil || err != nil {
		t.Fatalf("empty store: %q %v %v", id, r, err)
	}
	for i, target := range []string{"/a", "/a", "/b"} {
		r := &report.Run{Target: target, SiegeKitVersion: strconv.Itoa(i), Started: time.Date(2026, 11, 18, 1, 0, i, 0, time.UTC)}
		if _, err := s.Save(r, "app"); err != nil {
			t.Fatal(err)
		}
	}
	// A run that cannot be read is passed over.
	if err := os.WriteFile(filepath.Join(s.Dir, "20261118T020000Z-app.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, r, err := s.Latest("/a")
	if err != nil || id != "20261118T010001Z-app" || r.SiegeKitVersion != "1" {
		t.Fatalf("latest /a: %q %+v %v", id, r, err)
	}
	if id, _, _ := s.Latest("/c"); id != "" {
		t.Errorf("latest /c: %q", id)
	}
}

// A finding that one run could not check again stays in the baseline of
// the next comparison: it is fixed or still present later, never new.
func TestComparisonCarriesNotRechecked(t *testing.T) {
	x := f("x", "gitleaks")
	run1 := &report.Run{Findings: []findings.Finding{x}}
	run2 := &report.Run{Plugins: []report.PluginResult{{ID: "gitleaks", Status: report.Failed}}}
	run2.Comparison = Comparison("r1", run1, run2)
	if len(run2.Comparison.NotRechecked) != 1 {
		t.Fatalf("run 2: %+v", run2.Comparison)
	}
	still := &report.Run{Plugins: []report.PluginResult{{ID: "gitleaks", Status: report.Ran}}, Findings: []findings.Finding{x}}
	if c := Comparison("r2", run2, still); len(c.New) != 0 || c.StillPresent != 1 {
		t.Errorf("still present: %+v", c)
	}
	fixed := &report.Run{Plugins: []report.PluginResult{{ID: "gitleaks", Status: report.Ran}}}
	if c := Comparison("r2", run2, fixed); len(c.Fixed) != 1 {
		t.Errorf("fixed: %+v", c)
	}
	failedAgain := &report.Run{Plugins: []report.PluginResult{{ID: "gitleaks", Status: report.Failed}}}
	if c := Comparison("r2", run2, failedAgain); len(c.NotRechecked) != 1 {
		t.Errorf("failed again: %+v", c)
	}
	if n := (&report.Comparison{}).VersionNote("1.0"); !strings.Contains(n, "an unknown version") {
		t.Errorf("note %q", n)
	}
}
