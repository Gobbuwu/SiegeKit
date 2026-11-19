package findings

import (
	"strings"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	for s := Info; s <= Critical; s++ {
		got, err := ParseSeverity(s.String())
		if err != nil || got != s {
			t.Fatalf("%v: got %v, %v", s, got, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDedupeAcrossToolsByCWE(t *testing.T) {
	a := Finding{RuleID: "semgrep.sqli", Severity: Medium, CWEs: []string{"CWE-89"}, Location: Location{URI: "app.py", StartLine: 10}, Sources: []Source{{"semgrep", "semgrep.sqli"}}}
	b := Finding{RuleID: "B608", Severity: High, CWEs: []string{"CWE-89"}, Location: Location{URI: "app.py", StartLine: 10}, Sources: []Source{{"bandit", "B608"}}}
	c := Finding{RuleID: "B608", Severity: Low, CWEs: []string{"CWE-89"}, Location: Location{URI: "app.py", StartLine: 11}, Sources: []Source{{"bandit", "B608"}}}
	out := Dedupe([]Finding{a, b, c})
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	if out[0].Severity != High || len(out[0].Sources) != 2 {
		t.Fatalf("merged finding wrong: %+v", out[0])
	}
	if out[1].Location.StartLine != 11 {
		t.Fatalf("sort order wrong: %+v", out)
	}
}

func TestDedupeDoesNotAliasInput(t *testing.T) {
	src := []Source{{"x", "r"}}
	in := []Finding{{RuleID: "r", Sources: src}, {RuleID: "r", Sources: []Source{{"y", "r"}}}}
	Dedupe(in)
	if len(src) != 1 || len(in[0].Sources) != 1 {
		t.Fatal("Dedupe modified its input")
	}
}

func TestMaskSecret(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"abc":                  "***",
		"AKIAABCDEFGHIJKLMNOP": "AKIA****************", // gitleaks:allow (AWS's documented fake key format, test data)
		"sk-1234567890abcdefghijklmnopqrstuvwxyz": "sk-1****************",
	} {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityText(t *testing.T) {
	var s Severity
	if err := s.UnmarshalText([]byte("HIGH")); err != nil || s != High {
		t.Fatalf("got %v %v", s, err)
	}
	if err := s.UnmarshalText([]byte("nope")); err == nil {
		t.Fatal("expected error")
	}
	if b, _ := Critical.MarshalText(); string(b) != "critical" {
		t.Fatalf("got %s", b)
	}
	if Severity(99).String() != "unknown" {
		t.Fatal("out-of-range severity should be unknown")
	}
}

func TestDedupeKeepsDistinctAdvisories(t *testing.T) {
	loc := Location{URI: "requirements.txt", StartLine: 1}
	a := Finding{RuleID: "CVE-2019-14234", Family: "sca", CWEs: []string{"CWE-89"}, Location: loc}
	b := Finding{RuleID: "CVE-2019-14235", Family: "sca", CWEs: []string{"CWE-89"}, Location: loc}
	c := Finding{RuleID: "CVE-2019-14234", Family: "sca", Location: loc, Sources: []Source{{Plugin: "osv", RuleID: "CVE-2019-14234"}}}
	if out := Dedupe([]Finding{a, b, c}); len(out) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(out), out)
	}
}

func TestRedactCredentials(t *testing.T) {
	f := Finding{RuleID: "B105", Family: "sast", CWEs: []string{"CWE-259"},
		Message: "Possible hardcoded password: 'ghp_abcdefghijklmnop' and \"hunter22\"", Snippet: `TOKEN = "ghp_abcdefghijklmnop"`}
	f.RedactCredentials()
	if strings.Contains(f.Message+f.Snippet, "efghij") || strings.Contains(f.Message, "hunter22") {
		t.Fatalf("credential kept: %+v", f)
	}
	if f.Message != "Possible hardcoded password: 'ghp_****************' and \"hunt****\"" {
		t.Errorf("message %q", f.Message)
	}
	other := Finding{RuleID: "B602", Family: "sast", CWEs: []string{"CWE-78"}, Message: "call 'sh'", Snippet: "x"}
	other.RedactCredentials()
	if other.Message != "call 'sh'" || other.Snippet != "x" {
		t.Errorf("unrelated finding changed: %+v", other)
	}
}

func TestSafeHelpURI(t *testing.T) {
	for u, want := range map[string]bool{
		"https://bandit.readthedocs.io/en/1.9.4/plugins/b602.html": true,
		"http://example.com/rule":                                  false,
		"javascript:alert(1)":                                      false,
		"https://user:pw@example.com/":                             false,
		"https:opaque":                                             false,
		"/relative":                                                false,
		"https://example.com/" + strings.Repeat("a", 2048):         false,
	} {
		if got := SafeHelpURI(u) != ""; got != want {
			t.Errorf("%.60q: kept %v, want %v", u, got, want)
		}
	}
}

func TestDedupeKeepsHelpURI(t *testing.T) {
	a := Finding{RuleID: "x", CWEs: []string{"CWE-89"}, Location: Location{URI: "a.py", StartLine: 1}, Sources: []Source{{"semgrep", "x"}}}
	b := a
	b.Sources = []Source{{"bandit", "B608"}}
	b.HelpURI = "https://example.com/b608"
	if out := Dedupe([]Finding{a, b}); len(out) != 1 || out[0].HelpURI != b.HelpURI {
		t.Fatalf("help link lost: %+v", out)
	}
}
