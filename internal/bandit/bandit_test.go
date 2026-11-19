package bandit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// Shape of Bandit 1.9 JSON output (fields SiegeKit reads).
const sample = `{"errors":[],"generated_at":"2026-11-19T00:00:00Z","metrics":{},"results":[
{"code":"3 def run(cmd):\n4     return subprocess.call(cmd, shell=True)\n","col_offset":11,"filename":"/target/app.py",
 "issue_confidence":"HIGH","issue_cwe":{"id":78,"link":"https://cwe.mitre.org/data/definitions/78.html"},
 "issue_severity":"HIGH","issue_text":"subprocess call with shell=True identified, security issue.",
 "line_number":4,"line_range":[4],"more_info":"https://bandit.readthedocs.io/","test_id":"B602",
 "test_name":"subprocess_popen_with_shell_equals_true"},
{"filename":"/target/a.py","issue_severity":"LOW","issue_confidence":"MEDIUM","line_number":1,"test_id":"B404","test_name":"blacklist","issue_text":"x"}]}`

func TestToFindings(t *testing.T) {
	fs, err := ToFindings(strings.NewReader(sample), Options{Plugin: "bandit", Family: "sast", MountPath: "/target"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings", len(fs))
	}
	f := fs[0]
	if f.RuleID != "B602" || f.Severity != findings.High || f.Location.URI != "app.py" || f.Location.StartLine != 4 ||
		len(f.CWEs) != 1 || f.CWEs[0] != "CWE-78" || f.Confidence != "high" || f.Fingerprint == "" {
		t.Errorf("finding %+v", f)
	}
	if fs[1].Severity != findings.Low || fs[1].CWEs != nil {
		t.Errorf("finding %+v", fs[1])
	}
}

func TestRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":     "nope",
		"no results":   `{"errors":[]}`,
		"missing rule": `{"results":[{"filename":"a.py"}]}`,
	} {
		if _, err := ToFindings(strings.NewReader(doc), Options{Plugin: "b", Family: "sast"}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ToFindings(strings.NewReader(sample), Options{}); err == nil {
		t.Error("missing options accepted")
	}
	big := bytes.Repeat([]byte(" "), MaxSize+1)
	if _, err := ToFindings(bytes.NewReader(big), Options{Plugin: "b", Family: "sast"}); err == nil {
		t.Error("oversize accepted")
	}
}

func FuzzBandit(f *testing.F) {
	f.Add([]byte(sample))
	f.Fuzz(func(t *testing.T, b []byte) {
		ToFindings(bytes.NewReader(b), Options{Plugin: "b", Family: "sast", MountPath: "/target"})
	})
}

// Bandit reports results hidden by "# nosec" only as totals: a bare
// comment in "nosec", one naming the test in "skipped_tests" (checked with
// Bandit 1.9.4).
func TestSuppressedCount(t *testing.T) {
	for _, tc := range []struct {
		report string
		want   int
	}{
		{`{"results":[],"metrics":{"_totals":{"nosec":1,"skipped_tests":1}}}`, 2},
		{`{"results":[]}`, 0},
		{`{"results":[],"metrics":{"_totals":{"nosec":-5,"skipped_tests":3}}}`, 3},
		{`{"results":[],"metrics":{"_totals":{"nosec":9223372036854775807,"skipped_tests":9223372036854775807}}}`, 2 << 30},
	} {
		n := -1
		if _, err := ToFindings(strings.NewReader(tc.report), Options{Plugin: "bandit", Family: "sast", Suppressed: &n}); err != nil {
			t.Fatal(err)
		}
		if n != tc.want {
			t.Errorf("%s: suppressed %d, want %d", tc.report, n, tc.want)
		}
	}
}
