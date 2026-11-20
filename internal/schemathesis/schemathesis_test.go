package schemathesis

import (
	"os"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

var opt = Options{Plugin: "schemathesis", Family: "api", Origin: "http://127.0.0.1:18090", BasePath: "/api", BaseKnown: true}

// The report of a real run (Schemathesis 4.33.4, 2026-11-20) against a test
// API whose GET /api/items/{id} answers 500 for negative ids.
func TestReal(t *testing.T) {
	f, err := os.Open("testdata/report-4.33.4.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fs, err := ToFindings(f, opt)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Finding{}
	for _, x := range fs {
		got[x.RuleID+" "+x.Location.URI] = x
	}
	want := map[string]findings.Severity{
		"ST101 http://127.0.0.1:18090/api/items/{id}": findings.Medium,
		"ST101 http://127.0.0.1:18090/api/items":      findings.Medium,
		"ST103 http://127.0.0.1:18090/api/items/{id}": findings.Low,
		"ST204 http://127.0.0.1:18090/api/items":      findings.Low,
		"ST204 http://127.0.0.1:18090/api/items/{id}": findings.Low,
	}
	if len(got) != len(want) || len(fs) != len(want) {
		t.Fatalf("got %d findings %v, want %v", len(fs), got, want)
	}
	for k, sev := range want {
		x, ok := got[k]
		if !ok || x.Severity != sev || x.Fingerprint == "" || x.Sources[0].Plugin != "schemathesis" {
			t.Errorf("%s: %+v", k, x)
		}
	}
	if m := got["ST101 http://127.0.0.1:18090/api/items/{id}"].Message; m != "Server error (Schemathesis check ST101) for GET, TRACE requests to /api/items/{id} generated from the OpenAPI spec." {
		t.Errorf("message %q", m)
	}
}

func TestUnknownBase(t *testing.T) {
	f, _ := os.Open("testdata/report-4.33.4.json")
	defer f.Close()
	o := opt
	o.BasePath, o.BaseKnown = "", false
	fs, err := ToFindings(f, o)
	if err != nil || len(fs) == 0 {
		t.Fatal(err)
	}
	for _, x := range fs {
		if !strings.HasPrefix(x.Location.URI, "http://127.0.0.1:18090/items") || !strings.Contains(x.Message, "could not read the API's base path") {
			t.Errorf("%+v", x)
		}
	}
}

// A run that could not reach the API reports errors and is not a clean
// result.
func TestUnreachable(t *testing.T) {
	f, _ := os.Open("testdata/unreachable-4.33.4.json")
	defer f.Close()
	if _, err := ToFindings(f, opt); err == nil || !strings.Contains(err.Error(), "Network Error") {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalid(t *testing.T) {
	ok := `"complete":true,"operations":{"selected":1,"tested":1},"errors":[]`
	for _, in := range []string{
		``, `[]`, `{}`, `{"complete":true,"operations":{"tested":1}}`,
		("{" + ok + "}")[:20],
		`{"complete":false,"operations":{"selected":1,"tested":1},"failures":[]}`,
		`{"complete":true,"operations":{"selected":2,"tested":0},"failures":[]}`,
		`{` + ok + `,"failures":[{"code":"X1","title":"t","operations":["GET /a"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":[]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["GET a"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["get /a"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["GET /a b"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["GET /a\n"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["GET /é"]}]}`,
		`{` + ok + `,"failures":[{"code":"ST101","title":"t","operations":["GET /` + strings.Repeat("a", 2048) + `"]}]}`,
		`{` + ok + `,"failures":[]}` + strings.Repeat(" ", MaxSize),
	} {
		if fs, err := ToFindings(strings.NewReader(in), opt); err == nil {
			t.Errorf("%.60q accepted: %v", in, fs)
		}
	}
	if fs, err := ToFindings(strings.NewReader(`{`+ok+`,"failures":[]}`), opt); err != nil || fs == nil || len(fs) != 0 {
		t.Errorf("empty: %v %v", fs, err)
	}
	if _, err := ToFindings(strings.NewReader(`{}`), Options{}); err == nil {
		t.Error("no options accepted")
	}
}

func TestClean(t *testing.T) {
	in := `{"complete":true,"operations":{"selected":1,"tested":1},"failures":[{"code":"ST101","title":"a\u001b[31mb` + strings.Repeat("x", 300) + `","operations":["GET /a"]}]}`
	fs, err := ToFindings(strings.NewReader(in), opt)
	if err != nil || len(fs) != 1 {
		t.Fatal(err)
	}
	if strings.ContainsRune(fs[0].Title, 0x1b) || len([]rune(fs[0].Title)) != 200 {
		t.Errorf("title %q", fs[0].Title)
	}
}

func FuzzSchemathesis(f *testing.F) {
	b, err := os.ReadFile("testdata/report-4.33.4.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		fs, err := ToFindings(strings.NewReader(string(b)), opt)
		if err != nil {
			return
		}
		for _, x := range fs {
			if !strings.HasPrefix(x.Location.URI, opt.Origin+opt.BasePath+"/") || strings.ContainsAny(x.Location.URI, " \t\r\n") || x.Fingerprint == "" {
				t.Fatalf("%+v", x)
			}
		}
	})
}
