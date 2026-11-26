package publicmaps

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func cfgFor(t *testing.T) egress.Config {
	t.Helper()
	u, err := target.Parse("http://app.test:3000/")
	if err != nil {
		t.Fatal(err)
	}
	return egress.Config{Target: u, Version: "test", ReadOnly: true}
}

// useSite serves path -> body with 200, 404 for the rest, and records
// the paths asked for. A nil body is a target that does not answer.
func useSite(t *testing.T, s map[string][]byte) (Getter, *[]string) {
	t.Helper()
	var got []string
	oldSleep, oldNow := sleep, now
	get := func(_ context.Context, _ egress.Config, path string, max int64) (int, []byte, error) {
		if max != openapi.MaxSize {
			t.Errorf("max %d", max)
		}
		got = append(got, path)
		b, ok := s[path]
		switch {
		case !ok:
			return 404, []byte("not found"), nil
		case b == nil:
			return 0, nil, errors.New("no answer")
		}
		return 200, b, nil
	}
	sleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { sleep, now = oldSleep, oldNow })
	return get, &got
}

func TestProbeSpecs(t *testing.T) {
	script, err := os.ReadFile("../openapi/testdata/swagger-ui-init-juice-shop.js")
	if err != nil {
		t.Fatal(err)
	}
	html := []byte("<!doctype html><html></html>")
	get, got := useSite(t, map[string][]byte{
		"/openapi.json":           []byte(`{"openapi":"3.1.0","paths":{}}`),
		"/swagger.json":           html, // a single-page app answers every path
		"/v3/api-docs":            nil,
		"/api/swagger.json":       []byte("swagger: '2.0'\npaths: {}\n"),
		openapi.SwaggerUIInitPath: script,
	})
	p, err := ProbeSpecs(context.Background(), get, cfgFor(t), 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*got, Paths()) || len(Paths()) != 11 {
		t.Errorf("asked for %v", *got)
	}
	if p.Tried != 11 || p.Requests != 10 || len(p.Specs) != 3 {
		t.Fatalf("probe %+v", p)
	}
	var urls []string
	for _, s := range p.Specs {
		urls = append(urls, s.URL)
	}
	want := []string{"http://app.test:3000/openapi.json", "http://app.test:3000/api/swagger.json", "http://app.test:3000/api-docs/swagger-ui-init.js"}
	if !slices.Equal(urls, want) {
		t.Errorf("specs %v", urls)
	}
	if e := p.Specs[2]; !e.Embedded || e.Spec.Format != "json" || !strings.HasPrefix(string(e.Spec.Data), "{") ||
		e.Spec.Source != "http://app.test:3000/api-docs/swagger-ui-init.js (the spec in the Swagger UI setup script)" {
		t.Errorf("embedded spec %+v", e)
	}
	if f := p.First(); f == nil || f.Source != "http://app.test:3000/openapi.json" || f.Format != "json" {
		t.Errorf("First = %+v", f)
	}
	if (Probe{}).First() != nil {
		t.Error("First of nothing")
	}
}

func TestProbeSpecsRate(t *testing.T) {
	get, _ := useSite(t, map[string][]byte{})
	var waits []time.Duration
	sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	start := time.Now()
	now = func() time.Time { return start }
	if _, err := ProbeSpecs(context.Background(), get, cfgFor(t), 10); err != nil {
		t.Fatal(err)
	}
	if len(waits) != len(Paths())-1 {
		t.Fatalf("waits %v", waits)
	}
	for _, w := range waits {
		if w != 100*time.Millisecond {
			t.Errorf("wait %s, want 100ms at 10 per second", w)
		}
	}
}

func TestProbeSpecsCanceled(t *testing.T) {
	get, got := useSite(t, map[string][]byte{})
	ctx, cancel := context.WithCancel(context.Background())
	sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	if _, err := ProbeSpecs(ctx, get, cfgFor(t), 1); !errors.Is(err, context.Canceled) || len(*got) != 1 {
		t.Errorf("err %v, sent %v", err, *got)
	}
}

func TestFindings(t *testing.T) {
	p := Probe{Tried: 11, Specs: []Found{
		{URL: "http://app.test/openapi.json"},
		{URL: "http://app.test/api-docs/swagger-ui-init.js", Embedded: true},
	}}
	r := served.Result{Files: []served.File{
		{Name: "001-page.html", URL: "http://app.test/", Kind: served.Page},
		{Name: "002-script.js", URL: "http://app.test/app.js", Kind: served.Script},
		{Name: "003-source-map.map", URL: "http://app.test/app.js.map", Kind: served.SourceMap, Map: true},
		{Name: "004-source-map.map", URL: "http://app.test/s.css.map", Kind: served.SourceMap}, // not a source map
	}}
	fs := Findings(p, r)
	if len(fs) != 3 {
		t.Fatalf("got %d findings", len(fs))
	}
	for i, want := range []struct{ rule, uri, cwe string }{
		{"public-api-spec", "http://app.test/openapi.json", "CWE-200"},
		{"public-api-spec", "http://app.test/api-docs/swagger-ui-init.js", "CWE-200"},
		{"public-source-map", "http://app.test/app.js.map", "CWE-540"},
	} {
		f := fs[i]
		if f.RuleID != want.rule || f.Location.URI != want.uri || f.Severity != findings.Low || f.Family != Family ||
			!slices.Equal(f.CWEs, []string{want.cwe}) || len(f.Sources) != 1 || f.Sources[0].Plugin != ID || f.Fingerprint == "" {
			t.Errorf("finding %d: %+v", i, f)
		}
	}
	if !strings.Contains(fs[1].Message, "Swagger UI page (http://app.test/api-docs/)") {
		t.Errorf("embedded message %q", fs[1].Message)
	}
	if s := Summary(p, r); s != "found 2 API spec(s) at 11 path(s) tried, and 1 source map(s) for 1 script(s) and style(s)" {
		t.Errorf("Summary %q", s)
	}
}

// A block stops the spec probe at once (ADR 0071): the later paths are
// neither sent nor waited for.
func TestProbeSpecsStopsWhenBlocked(t *testing.T) {
	waits := 0
	oldSleep := sleep
	sleep = func(context.Context, time.Duration) error { waits++; return nil }
	t.Cleanup(func() { sleep = oldSleep })
	var got []string
	get := func(_ context.Context, _ egress.Config, path string, _ int64) (int, []byte, error) {
		got = append(got, path)
		if len(got) == 3 {
			return 403, nil, &egress.BlockedError{Block: &egress.Block{Reason: "test block"}}
		}
		return 404, []byte("not found"), nil
	}
	p, err := ProbeSpecs(context.Background(), get, cfgFor(t), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || waits != 2 || p.Tried != 3 || p.Requests != 3 || len(Paths()) <= 3 {
		t.Errorf("sent %v, %d waits, %+v", got, waits, p)
	}
}
