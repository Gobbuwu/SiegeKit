package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

func run(status Status, fs ...findings.Finding) *Run {
	return &Run{
		SiegeKitVersion: "0.0.0-test", Target: "./app", Mode: "local",
		Started:  time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		Plugins:  []PluginResult{{ID: "gitleaks", Family: "secrets", Tool: "gitleaks", Version: "8", Status: Ran}, {ID: "semgrep", Family: "sast", Tool: "semgrep", Version: "1", Status: status}},
		Findings: fs,
	}
}

func TestHeadlineNeverClaimsSecure(t *testing.T) {
	h := run(Ran).Headline()
	if !strings.Contains(h, "does not mean the application is secure") {
		t.Fatalf("clean headline must carry the caveat: %q", h)
	}
	for _, r := range []*Run{run(Ran), run(Failed), {}} {
		var b bytes.Buffer
		if err := WriteHTML(&b, r); err != nil {
			t.Fatal(err)
		}
		// The required caveat contains "is secure."; remove it before checking.
		low := strings.ReplaceAll(strings.ToLower(b.String()), "does not mean the application is secure.", "")
		for _, banned := range []string{"passed", "all clear", "is secure.", "you are safe"} {
			if strings.Contains(low, banned) {
				t.Errorf("report contains banned wording %q", banned)
			}
		}
		if !strings.Contains(b.String(), "Not tested by SiegeKit") {
			t.Error("report missing 'Not tested' section")
		}
	}
	if got := (&Run{}).Headline(); !strings.Contains(got, "Nothing was tested") {
		t.Errorf("empty run headline: %q", got)
	}
}

func TestExitCodes(t *testing.T) {
	high := findings.Finding{RuleID: "x", Severity: findings.High}
	low := findings.Finding{RuleID: "y", Severity: findings.Low}
	cases := []struct {
		r    *Run
		want int
	}{
		{run(Ran), ExitClean},
		{run(Failed), ExitIncomplete},
		{run(TimedOut), ExitIncomplete},
		{run(Ran, high), ExitFindings},
		{run(Failed, high), ExitFindings},
		{run(Ran, low), ExitClean},
		{&Run{}, ExitIncomplete},
	}
	for i, c := range cases {
		if got := c.r.ExitCode(findings.Medium, false); got != c.want {
			t.Errorf("case %d: exit %d, want %d", i, got, c.want)
		}
	}
}

func TestHTMLEscapesToolOutput(t *testing.T) {
	evil := findings.Finding{RuleID: "xss", Title: `<script>alert(1)</script>`, Message: `<img src=x onerror=alert(1)>`, Snippet: `"><svg onload=1>`, Location: findings.Location{URI: `javascript:alert(1)`}}
	var b bytes.Buffer
	if err := WriteHTML(&b, run(Ran, evil)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, raw := range []string{"<script>alert", "<img src=x", "<svg onload"} {
		if strings.Contains(out, raw) {
			t.Errorf("unescaped tool output in HTML: %q", raw)
		}
	}
	if !strings.Contains(out, "default-src 'none'") {
		t.Error("missing Content-Security-Policy")
	}
	if strings.Contains(out, "<script") || strings.Contains(out, "http://") {
		t.Error("report must not contain scripts or external resources")
	}
}

func TestSARIFRoundTrip(t *testing.T) {
	f := findings.Finding{RuleID: "sqli", Title: "SQL injection", Message: "m", Severity: findings.High, CWEs: []string{"CWE-89"}, Location: findings.Location{URI: "a.py", StartLine: 3}, Sources: []findings.Source{{Plugin: "semgrep", RuleID: "sqli"}}}
	f.ComputeFingerprint()
	var b bytes.Buffer
	if err := WriteSARIF(&b, run(Ran, f)); err != nil {
		t.Fatal(err)
	}
	l, err := sarif.Read(&b)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.ToFindings(l, sarif.Options{Plugin: "siegekit", Family: "sast"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Fingerprint != f.Fingerprint || fs[0].Severity != findings.High {
		t.Fatalf("round trip mismatch: %+v", fs)
	}
}

func TestAgentFacingFields(t *testing.T) {
	f := findings.Finding{RuleID: "B602", Title: "shell", Severity: findings.High, Location: findings.Location{URI: "a.py", StartLine: 3},
		HelpURI: "https://bandit.readthedocs.io/x?a=1&b=2", Sources: []findings.Source{{Plugin: "bandit", RuleID: "B602"}}}
	f.ComputeFingerprint()
	var j, s, h bytes.Buffer
	if err := WriteJSON(&j, run(Ran, f)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion int `json:"schemaVersion"`
		Target        string
		Findings      []findings.Finding
	}
	if err := json.Unmarshal(j.Bytes(), &got); err != nil || got.SchemaVersion != SchemaVersion || got.Target != "./app" || got.Findings[0].HelpURI != f.HelpURI {
		t.Fatalf("report.json: %+v %v\n%s", got, err, j.String())
	}
	if err := WriteSARIF(&s, run(Ran, f)); err != nil || !strings.Contains(s.String(), `"helpUri": "https://bandit.readthedocs.io/x?a=1\u0026b=2"`) {
		t.Errorf("SARIF rule has no helpUri: %v\n%s", err, s.String())
	}
	if err := WriteHTML(&h, run(Ran, f)); err != nil || !strings.Contains(h.String(), `<a href="https://bandit.readthedocs.io/x?a=1&amp;b=2" rel="noreferrer">`) {
		t.Errorf("HTML has no help link: %v", err)
	}
}

// TestHTMLShowsProxyCounts checks that the HTML report shows, per check,
// the requests the target answered and what the egress proxy refused
// (ADR 0023), escaped.
func TestHTMLShowsProxyCounts(t *testing.T) {
	r := run(Ran)
	r.Plugins[1].Requests, r.Plugins[1].Refused, r.Plugins[1].RefusedTo = 94, 2, []string{"CONNECT other.test:443", "GET <b>x"}
	r.Plugins[1].Input = "OpenAPI spec <x>.yaml"
	var b bytes.Buffer
	if err := WriteHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	want := "Requests answered by the target: 94. Refused by SiegeKit: 2 (<code>CONNECT other.test:443</code>, <code>GET &lt;b&gt;x</code>)."
	if !strings.Contains(out, want) {
		t.Errorf("HTML lacks %q", want)
	}
	if !strings.Contains(out, "<br>Tested from: OpenAPI spec &lt;x&gt;.yaml") {
		t.Error("HTML lacks the escaped input")
	}
	if strings.Count(out, "Requests answered by the target") != 1 {
		t.Error("counts shown for a check with no requests")
	}
}

// TestCheckCauses checks that a skip with no valid cause is never read as
// an acceptable skip (ADR 0041).
func TestCheckCauses(t *testing.T) {
	r := &Run{Plugins: []PluginResult{
		{ID: "a", Status: Skipped, Cause: CauseNoFiles, Reason: "no files matching *.go"},
		{ID: "b", Status: Skipped, Reason: "no cause"},
		{ID: "c", Status: Skipped, Cause: "no files", Reason: "misspelled cause"},
		{ID: "d", Status: Ran},
		{ID: "e", Status: Failed, Reason: "tool error"},
	}}
	if bad := r.CheckCauses(); !slices.Equal(bad, []string{"b", "c"}) {
		t.Fatalf("CheckCauses = %v", bad)
	}
	if r.Plugins[0].Status != Skipped || r.Plugins[1].Status != Failed || r.Plugins[2].Status != Failed || r.Plugins[4].Status != Failed {
		t.Errorf("statuses: %+v", r.Plugins)
	}
	if !strings.Contains(r.Plugins[1].Reason, "SiegeKit bug") || r.Complete() {
		t.Errorf("a skip with no cause must make the run incomplete: %+v", r.Plugins[1])
	}
	for _, c := range Causes {
		if !c.Valid() {
			t.Errorf("%q not valid", c)
		}
	}
	if !CauseDeclined.MissingDependency() || !CauseMissingDependency.MissingDependency() || CauseNoFiles.MissingDependency() || CauseTargetMode.MissingDependency() || CauseProfile.MissingDependency() {
		t.Error("MissingDependency must be true for missing-dependency and declined only")
	}
	var j bytes.Buffer
	if err := WriteJSON(&j, r); err != nil || !strings.Contains(j.String(), `"cause": "no-files"`) {
		t.Errorf("report.json has no cause: %v\n%s", err, j.String())
	}
}

func TestGapsAndRequireComplete(t *testing.T) {
	r := run(Ran)
	r.Plugins = []PluginResult{{ID: "a", Status: Ran}, {ID: "b", Status: Ran}, {ID: "c", Status: Failed, Stop: StopMemoryKill}}
	for i := 0; i < MaxGaps+3; i++ {
		r.Plugins[0].AddGap(Gap{Cause: GapTooLarge, Path: fmt.Sprintf("big%d.json", i)})
	}
	r.Plugins[1].Completeness = Complete
	r.MarkCompleteness()
	if p := r.Plugins[0]; p.GapCount != MaxGaps+3 || len(p.Gaps) != MaxGaps || p.Completeness != WithGaps {
		t.Fatalf("gaps %d listed %d completeness %q", p.GapCount, len(p.Gaps), p.Completeness)
	}
	if r.Plugins[1].Completeness != Complete || r.Plugins[2].Completeness != "" {
		t.Fatalf("completeness %q %q", r.Plugins[1].Completeness, r.Plugins[2].Completeness)
	}
	if !strings.Contains(r.Plugins[0].GapNote(), "203 not checked: big0.json (too-large)") {
		t.Errorf("note %q", r.Plugins[0].GapNote())
	}
	r.Plugins = r.Plugins[:2] // without the stopped check
	if got := r.ExitCode(findings.Medium, false); got != ExitClean {
		t.Errorf("gaps alone: exit %d, want %d", got, ExitClean)
	}
	if got := r.ExitCode(findings.Medium, true); got != ExitIncomplete {
		t.Errorf("gaps with --require-complete: exit %d, want %d", got, ExitIncomplete)
	}
	plain := run(Ran)
	plain.MarkCompleteness()
	if plain.Plugins[0].Completeness != NotProven {
		t.Errorf("a check with no signal must be not proven, got %q", plain.Plugins[0].Completeness)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"gapCount": 203`, `"cause": "too-large"`, `"completeness": "gaps"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report.json lacks %s", want)
		}
	}
}
