package findings

import "testing"

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
		"AKIAABCDEFGHIJKLMNOP": "AKIA****************",
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
