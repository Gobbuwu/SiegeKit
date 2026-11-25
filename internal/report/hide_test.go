package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// Hide leaves the value out of every report format, wherever a tool put it.
func TestHide(t *testing.T) {
	const secret, short = "s3cr3t-bypass-0123456789abcdefXY", "s3cr3t-bypass"
	r := &Run{
		SiegeKitVersion: "test", Target: "https://app.test/", Mode: "deployed",
		Started: time.Unix(0, 0).UTC(), Finished: time.Unix(1, 0).UTC(),
		Plugins: []PluginResult{{
			ID: "nuclei", Family: "dast", Tool: "nuclei", Status: Ran, Findings: 1,
			Reason: "answer echoed x-vercel-protection-bypass: " + secret, RefusedTo: []string{"GET " + secret},
			Gaps: []Gap{{Path: secret}},
		}},
		Findings: []findings.Finding{{
			RuleID: "echo", Title: "Header echoed", Message: "request headers: " + secret + ", " + short, Severity: findings.Info,
			Location: findings.Location{URI: "https://app.test/headers"}, Snippet: "<pre>" + secret + "</pre>", Family: "dast",
			Sources: []findings.Source{{Plugin: "nuclei", RuleID: secret}},
		}},
	}
	r.Hide([]string{short, secret, ""}, "[hidden]")
	for _, w := range []struct {
		name  string
		write func(*bytes.Buffer, *Run) error
	}{
		{"json", func(b *bytes.Buffer, r *Run) error { return WriteJSON(b, r) }},
		{"sarif", func(b *bytes.Buffer, r *Run) error { return WriteSARIF(b, r) }},
		{"html", func(b *bytes.Buffer, r *Run) error { return WriteHTML(b, r) }},
	} {
		var b bytes.Buffer
		if err := w.write(&b, r); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), short) {
			t.Errorf("%s report holds the value", w.name)
		}
		if !strings.Contains(b.String(), "[hidden]") {
			t.Errorf("%s report does not say a value was hidden", w.name)
		}
	}
	if r.Findings[0].Message != "request headers: [hidden], [hidden]" {
		t.Errorf("message %q", r.Findings[0].Message)
	}
	if r.Plugins[0].Gaps[0].Path != "[hidden]" || r.Findings[0].Sources[0].RuleID != "[hidden]" {
		t.Errorf("nested fields not hidden: %+v %+v", r.Plugins[0].Gaps, r.Findings[0].Sources)
	}
	if !r.Started.Equal(time.Unix(0, 0)) {
		t.Error("time changed")
	}
}
