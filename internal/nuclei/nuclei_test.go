package nuclei

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// headers-3.11.1.jsonl is real Nuclei 3.11.1 output (-jsonl -omit-raw) of
// the http-missing-security-headers template against a server that sets
// no security headers: ten results, one per matcher.
func TestRecordedHeaders(t *testing.T) {
	b, err := os.ReadFile("testdata/headers-3.11.1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ToFindings(bytes.NewReader(b), Options{Plugin: "nuclei", Family: "dast"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want the 10 matchers merged into 1", len(fs))
	}
	f := fs[0]
	want := "HTTP Missing Security Headers at http://127.0.0.1:8000/: content-security-policy, cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-resource-policy, permissions-policy, referrer-policy, strict-transport-security, x-content-type-options, x-frame-options, x-permitted-cross-domain-policies"
	if f.Message != want {
		t.Errorf("message\n got %q\nwant %q", f.Message, want)
	}
	if f.RuleID != "http-missing-security-headers" || f.Title != "HTTP Missing Security Headers" || f.Severity != findings.Info ||
		len(f.CWEs) != 1 || f.CWEs[0] != "CWE-693" || f.Location.URI != "http://127.0.0.1:8000/" ||
		f.HelpURI != "https://cloud.projectdiscovery.io/public/http-missing-security-headers" || f.Fingerprint == "" ||
		f.Family != "dast" || f.Sources[0] != (findings.Source{Plugin: "nuclei", RuleID: "http-missing-security-headers"}) {
		t.Errorf("finding %+v", f)
	}
}

func TestConvert(t *testing.T) {
	doc := `{"template-id":"git-config","info":{"name":"Git Config - Detect","severity":"medium","classification":{"cwe-id":["cwe-200","CWE-200","bogus"]}},"matched-at":"http://app.test/.git/config","extracted-results":["token=SECRET"],"template-url":"javascript:alert(1)"}

{"template-id":"x","info":{"severity":"critical"},"matched-at":"http://app.test/a"}
{"template-id":"x","info":{"severity":"critical"},"matched-at":"http://app.test/b","matcher-name":"m"}
{"template-id":"cookies","matched-at":"app.test:8080","url":"http://app.test:8080/"}
{"template-id":"odd","matched-at":"app.test:8080","url":"not a url"}
`
	fs, err := ToFindings(strings.NewReader(doc), Options{Plugin: "nuclei", Family: "dast"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 5 {
		t.Fatalf("got %d findings", len(fs))
	}
	g := fs[0]
	if g.Severity != findings.Medium || len(g.CWEs) != 1 || g.CWEs[0] != "CWE-200" || g.HelpURI != "" || strings.Contains(g.Message+g.Snippet, "SECRET") {
		t.Errorf("git-config %+v", g)
	}
	if fs[1].Title != "x" || fs[1].Message != "x at http://app.test/a" || fs[1].Severity != findings.Critical || fs[1].Fingerprint == fs[2].Fingerprint {
		t.Errorf("x %+v %+v", fs[1], fs[2])
	}
	if fs[2].Message != "x at http://app.test/b: m" {
		t.Errorf("x/b %q", fs[2].Message)
	}
	// host:port only: the request URL is used; kept as is if that is no URL.
	if fs[3].Location.URI != "http://app.test:8080/" || fs[4].Location.URI != "app.test:8080" {
		t.Errorf("locations %q %q", fs[3].Location.URI, fs[4].Location.URI)
	}
	for s, want := range map[string]findings.Severity{"HIGH": findings.High, "low": findings.Low, "unknown": findings.Info, "": findings.Info} {
		if severity(s) != want {
			t.Errorf("severity(%q)", s)
		}
	}
	// An empty report is no findings, not an error: Nuclei writes an empty
	// file when nothing matches.
	if fs, err := ToFindings(strings.NewReader(""), Options{Plugin: "n", Family: "dast"}); err != nil || len(fs) != 0 {
		t.Errorf("empty: %v %v", fs, err)
	}
}

func TestRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       "nope\n",
		"no template id": `{"matched-at":"http://a/"}`,
		"no matched-at":  `{"template-id":"x"}`,
		"long line":      `{"template-id":"x","matched-at":"` + strings.Repeat("a", MaxLine) + `"}`,
	} {
		if _, err := ToFindings(strings.NewReader(doc), Options{Plugin: "n", Family: "dast"}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ToFindings(strings.NewReader(""), Options{}); err == nil {
		t.Error("missing options accepted")
	}
	big := bytes.Repeat([]byte("\n"), MaxSize+1)
	if _, err := ToFindings(bytes.NewReader(big), Options{Plugin: "n", Family: "dast"}); err == nil {
		t.Error("oversize accepted")
	}
}

func FuzzNuclei(f *testing.F) {
	if b, err := os.ReadFile("testdata/headers-3.11.1.jsonl"); err == nil {
		f.Add(b)
	}
	f.Add([]byte(`{"template-id":"x","matched-at":"http://a/","matcher-name":"m","info":{"classification":{"cwe-id":["cwe-1"]}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fs, err := ToFindings(bytes.NewReader(b), Options{Plugin: "n", Family: "dast"})
		for _, x := range fs {
			if err != nil || x.Fingerprint == "" || x.RuleID == "" {
				t.Fatalf("finding %+v with error %v", x, err)
			}
		}
	})
}
