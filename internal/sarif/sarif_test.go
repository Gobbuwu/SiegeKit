package sarif

import (
	"bytes"
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
	{"ruleId":"aws","message":{"text":"secret"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".env"},"region":{"startLine":1,"snippet":{"text":"AKIAABCDEFGHIJKLMNOP"}}}}]}]}]}`
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
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		if _, err := ToFindings(l, Options{Plugin: "p", Family: "secrets"}); err != nil {
			t.Fatal(err)
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
		if got := relURI(in, "/target"); got != want {
			t.Errorf("relURI(%q) = %q, want %q", in, got, want)
		}
	}
	if got := relURI("/target/a", ""); got != "/target/a" {
		t.Errorf("empty mount changed URI: %q", got)
	}
}

func TestUnknownParser(t *testing.T) {
	if _, err := ToFindings(&Log{}, Options{Plugin: "p", Family: "iac", Parser: "x"}); err == nil {
		t.Fatal("expected rejection")
	}
}
