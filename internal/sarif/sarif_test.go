package sarif

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

const sample = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "demo", "rules": [
      {"id": "sqli", "shortDescription": {"text": "SQL injection"},
       "properties": {"tags": ["security", "external/cwe/cwe-89", "CWE-0"], "security-severity": "9.8"}},
      {"id": "weak-hash", "name": "WeakHash", "properties": {"cwe": "CWE-0328"}}
    ]}},
    "results": [
      {"ruleId": "sqli", "level": "warning", "message": {"text": "query built from input"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42}}}]},
      {"ruleIndex": 1, "level": "note", "message": {"text": "md5 used"}},
      {"ruleId": "unknown", "message": {"text": "default level"}}
    ]
  }]
}`

func TestToFindings(t *testing.T) {
	l, err := Read(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ToFindings(l, Options{Plugin: "demo", Family: "sast"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("want 3, got %d", len(fs))
	}
	if fs[0].Severity != findings.Critical || fs[0].Title != "SQL injection" || fs[0].Location.StartLine != 42 {
		t.Errorf("first finding wrong: %+v", fs[0])
	}
	if len(fs[0].CWEs) != 1 || fs[0].CWEs[0] != "CWE-89" {
		t.Errorf("CWEs wrong: %v", fs[0].CWEs)
	}
	if fs[1].RuleID != "weak-hash" || fs[1].Severity != findings.Low || fs[1].CWEs[0] != "CWE-328" {
		t.Errorf("ruleIndex lookup wrong: %+v", fs[1])
	}
	if fs[2].Severity != findings.Medium {
		t.Errorf("missing level should default to warning/medium, got %v", fs[2].Severity)
	}
	for _, f := range fs {
		if f.Fingerprint == "" {
			t.Error("fingerprint not set")
		}
	}
}

func TestSecretsAreMasked(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[
	{"ruleId":"aws","message":{"text":"secret"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".env"},"region":{"startLine":1,"snippet":{"text":"AKIAABCDEFGHIJKLMNOP"}}}}]}]}]}` // gitleaks:allow (fake key, test data)
	l, err := Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := ToFindings(l, Options{Plugin: "gitleaks", Family: "secrets"})
	if strings.Contains(fs[0].Snippet, "ABCDEFGH") {
		t.Fatalf("secret not masked: %q", fs[0].Snippet)
	}
}

func TestRejects(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"version":"2.0.0","runs":[]}`)); err == nil {
		t.Error("expected version error")
	}
	if _, err := Read(strings.NewReader(`not json`)); err == nil {
		t.Error("expected decode error")
	}
	if _, err := ToFindings(&Log{}, Options{}); err == nil {
		t.Error("expected options error")
	}
}

func FuzzSARIF(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{"ruleIndex":-5}]}]}`))
	// ZAP's shape: no helpUri, links in the rule's "references" property.
	f.Add([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP","rules":[{"id":"10038","properties":{"references":["javascript:x",7,"https://example.com/csp"]},"relationships":[{"target":{"id":"693","toolComponent":{"name":"CWE"}}}]}]}},"results":[{"ruleId":"10038","ruleIndex":0,"level":"warning","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"http://app.test/"}}}]}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		// Every parser, so tool-specific paths such as ZAP's help links
		// are fuzzed too.
		for _, p := range Parsers {
			fs, err := ToFindings(l, Options{Plugin: "p", Family: "secrets", Parser: p})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range fs {
				if f.HelpURI != "" && findings.SafeHelpURI(f.HelpURI) == "" {
					t.Fatalf("%s: unsafe help link %q", p, f.HelpURI)
				}
			}
		}
	})
}

// Shapes below are copied from real gitleaks 8.30.1 and checkov 3.4.5 output.
func TestParserVariants(t *testing.T) {
	gitleaks := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat","shortDescription":{"text":"GitHub token"}}]}},"results":[
	{"ruleId":"github-pat","message":{"text":"found"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/config.py"},"region":{"startLine":1,"snippet":{"text":"REDACTED"}}}}]}]}]}`
	checkov := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Checkov","rules":[{"id":"CKV_DOCKER_8","name":"Ensure the last USER is not root"}]}},"results":[
	{"ruleId":"CKV_DOCKER_8","ruleIndex":0,"level":"error","message":{"text":"root"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"target/Dockerfile"},"region":{"startLine":3}}}]}]}]}`
	for _, tc := range []struct {
		doc, parser, family, uri string
		want                     findings.Severity
	}{
		{gitleaks, "sarif-gitleaks", "secrets", "config.py", findings.High},
		{checkov, "sarif-checkov", "iac", "Dockerfile", findings.Medium},
		{checkov, "sarif", "iac", "Dockerfile", findings.High},
	} {
		l, err := Read(strings.NewReader(tc.doc))
		if err != nil {
			t.Fatal(err)
		}
		fs, err := ToFindings(l, Options{Plugin: "p", Family: tc.family, Parser: tc.parser, MountPath: "/target"})
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 || fs[0].Severity != tc.want || fs[0].Location.URI != tc.uri {
			t.Errorf("%s: got %+v", tc.parser, fs)
		}
	}
}

func TestRelURI(t *testing.T) {
	for in, want := range map[string]string{
		"/target/a/b.go":        "a/b.go",
		"file:///target/a.go":   "a.go",
		"target/Dockerfile":     "Dockerfile",
		"/target/":              "/target/",
		"/targetx/a.go":         "/targetx/a.go",
		"app/main.go":           "app/main.go",
		"https://example.test/": "https://example.test/",
	} {
		if got := RelURI(in, "/target"); got != want {
			t.Errorf("RelURI(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RelURI("/target/a", ""); got != "/target/a" {
		t.Errorf("empty mount changed URI: %q", got)
	}
}

func TestUnknownParser(t *testing.T) {
	if _, err := ToFindings(&Log{}, Options{Plugin: "p", Family: "iac", Parser: "x"}); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestStripMount(t *testing.T) {
	cases := map[string]string{
		"aws-access-token has detected secret for file /target/cfg.py.": "aws-access-token has detected secret for file cfg.py.",
		"/target/a.py is bad":          "a.py is bad",
		"see file:///target/a.py":      "see a.py",
		`quoted "/target/x/y.go" path`: `quoted "x/y.go" path`,
		"src/target/x.py stays":        "src/target/x.py stays",
		"no path here":                 "no path here",
		"/targets/x.py is another dir": "/targets/x.py is another dir",
	}
	for in, want := range cases {
		if got := stripMount(in, "/target"); got != want {
			t.Errorf("stripMount(%q) = %q, want %q", in, got, want)
		}
	}
	if got := stripMount("/target/a", ""); got != "/target/a" {
		t.Errorf("empty mount changed the message: %q", got)
	}
}

// Results suppressed in the scanned code are left out and counted; a
// suppression that is only under review or was rejected leaves the result.
func TestSuppressedResults(t *testing.T) {
	const log = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[
{"ruleId":"G401","message":{"text":"a"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":5}}}],"suppressions":[{"kind":"inSource","justification":"test"}]},
{"ruleId":"G401","message":{"text":"b"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":6}}}],"suppressions":[{"kind":"inSource","status":"accepted"}]},
{"ruleId":"G401","message":{"text":"c"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":7}}}],"suppressions":[{"kind":"inSource","status":"rejected"}]},
{"ruleId":"G401","message":{"text":"d"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":8}}}],"suppressions":[{"kind":"external","status":"underReview"}]},
{"ruleId":"G401","message":{"text":"e"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":9}}}],"suppressions":[]}]}]}`
	l, err := Read(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	fs, err := ToFindings(l, Options{Plugin: "gosec", Family: "sast", Suppressed: &n})
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range fs {
		lines = append(lines, f.Location.StartLine)
	}
	if n != 2 || !slices.Equal(lines, []int{7, 8, 9}) {
		t.Errorf("suppressed %d, kept lines %v; want 2 and [7 8 9]", n, lines)
	}
	// Without a counter, suppressed results are still left out.
	if fs, _ := ToFindings(l, Options{Plugin: "gosec", Family: "sast"}); len(fs) != 3 {
		t.Errorf("without counter: %d findings", len(fs))
	}
}
