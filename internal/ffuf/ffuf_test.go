package ffuf

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// local-2.3.0.json is real ffuf 2.3.0 output (-ac -of json) against a
// static file server holding /.env, /.git/config and /admin/; local paths
// in the command line were replaced by the container paths.
func TestRecorded(t *testing.T) {
	b, err := os.ReadFile("testdata/local-2.3.0.json")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ToFindings(bytes.NewReader(b), Options{Plugin: "ffuf", Family: "dast"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http://127.0.0.1:18081/.env answered 200 (14 bytes, application/octet-stream)",
		"http://127.0.0.1:18081/.git/config answered 200 (7 bytes, application/octet-stream)",
		"http://127.0.0.1:18081/admin answered 301 (0 bytes), redirecting to /admin/",
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d", len(fs), len(want))
	}
	for i, f := range fs {
		if f.Message != want[i] || f.RuleID != RuleID || f.Severity != findings.Info || f.Family != "dast" ||
			!strings.HasPrefix(want[i], f.Location.URI+" ") || f.Fingerprint == "" || f.Sources[0] != (findings.Source{Plugin: "ffuf", RuleID: RuleID}) {
			t.Errorf("finding %d: %+v", i, f)
		}
	}
}

func TestEmptyAndDuplicates(t *testing.T) {
	fs, err := ToFindings(strings.NewReader(`{"results":[]}`), Options{Plugin: "ffuf", Family: "dast"})
	if err != nil || fs == nil || len(fs) != 0 {
		t.Errorf("empty: %v %v", fs, err)
	}
	two := `{"results":[{"status":200,"length":1,"url":"http://h/a"},{"status":200,"length":1,"url":"http://h/a"}]}`
	if fs, err := ToFindings(strings.NewReader(two), Options{Plugin: "ffuf", Family: "dast"}); err != nil || len(fs) != 1 {
		t.Errorf("duplicates: %d %v", len(fs), err)
	}
}

func TestRejects(t *testing.T) {
	opt := Options{Plugin: "ffuf", Family: "dast"}
	for name, in := range map[string]string{
		"not json":   "nope",
		"no results": `{"time":"x"}`,
		"bad url":    `{"results":[{"status":200,"url":"javascript:alert(1)"}]}`,
		"no host":    `{"results":[{"status":200,"url":"http:///x"}]}`,
		"bad status": `{"results":[{"status":0,"url":"http://h/x"}]}`,
		"too large":  `{"results":[` + strings.Repeat(" ", MaxSize) + `]}`,
	} {
		if _, err := ToFindings(strings.NewReader(in), opt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ToFindings(strings.NewReader(`{"results":[]}`), Options{}); err == nil {
		t.Error("missing options accepted")
	}
}

func FuzzFFUF(f *testing.F) {
	b, _ := os.ReadFile("testdata/local-2.3.0.json")
	f.Add(b)
	f.Add([]byte(`{"results":[]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		fs, err := ToFindings(bytes.NewReader(in), Options{Plugin: "ffuf", Family: "dast"})
		if err != nil {
			return
		}
		for _, x := range fs {
			if x.Severity != findings.Info || !strings.HasPrefix(x.Location.URI, "http") {
				t.Fatalf("bad finding %+v", x)
			}
		}
	})
}
