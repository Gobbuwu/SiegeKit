package report

import (
	"bytes"
	"encoding/json"
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
		if got := c.r.ExitCode(findings.Medium); got != c.want {
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
