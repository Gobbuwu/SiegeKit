// Package publicmaps reports the "attack maps" a web app serves to anyone
// (ADR 0046): an OpenAPI or Swagger spec, which lists the API's routes,
// and source maps, which give back the app's original source. Attack
// tools download both to choose what to test (Unit 42, "Remove public
// attack maps", 2026-11-11). Only GET requests are sent, so the check
// runs on deployed targets too.
package publicmaps

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/served"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "public-maps"
	Name   = "Public API specs and source maps"
	Family = "dast"
)

// Paths are the places a spec is looked for, in order: the default paths
// of ADR 0028, then the setup script of swagger-ui-express.
func Paths() []string {
	return append(slices.Clone(openapi.DefaultPaths), openapi.SwaggerUIInitPath)
}

// Found is one spec served on the target.
type Found struct {
	URL string
	// Embedded is true for a spec held in a Swagger UI setup script.
	Embedded bool
	Spec     openapi.Spec
}

// Probe is what ProbeSpecs found.
type Probe struct {
	Specs    []Found
	Tried    int // paths tried
	Requests int // GET requests the target answered
}

// Getter sends one GET and returns the status and body, as egress.Get.
type Getter func(ctx context.Context, cfg egress.Config, path string, max int64) (int, []byte, error)

// sleep and now are replaced in tests.
var (
	sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	now = time.Now
)

// ProbeSpecs sends one GET with get (egress.Get outside tests) for each of
// Paths, no faster than rate per second, following no redirects and
// reading at most openapi.MaxSize bytes, and returns every spec found. It
// fails only when ctx ends.
func ProbeSpecs(ctx context.Context, get Getter, cfg egress.Config, rate float64) (Probe, error) {
	var p Probe
	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}
	var last time.Time
	for _, path := range Paths() {
		if !last.IsZero() {
			if err := sleep(ctx, interval-now().Sub(last)); err != nil {
				return p, err
			}
		}
		if err := ctx.Err(); err != nil {
			return p, err
		}
		last = now()
		p.Tried++
		status, b, err := get(ctx, cfg, path, openapi.MaxSize)
		if status != 0 {
			p.Requests++
		}
		if err != nil || status != 200 {
			continue
		}
		embedded := path == openapi.SwaggerUIInitPath
		if embedded {
			if b, err = openapi.FromSwaggerUIInit(b); err != nil {
				continue
			}
		}
		format, err := openapi.Check(b)
		if err != nil {
			continue
		}
		u := cfg.Target.Origin() + path
		source := u
		if embedded {
			source += " (the spec in the Swagger UI setup script)"
		}
		p.Specs = append(p.Specs, Found{URL: u, Embedded: embedded, Spec: openapi.Spec{Data: b, Format: format, Source: source}})
	}
	return p, ctx.Err()
}

// First returns the first spec found, the one other checks use, or nil.
func (p Probe) First() *openapi.Spec {
	if len(p.Specs) == 0 {
		return nil
	}
	s := p.Specs[0].Spec
	return &s
}

// Maps returns the source maps among the served files.
func Maps(r served.Result) []served.File {
	var out []served.File
	for _, f := range r.Files {
		if f.Kind == served.SourceMap && f.Map {
			out = append(out, f)
		}
	}
	return out
}

// Summary says what was checked and found, for reports.
func Summary(p Probe, r served.Result) string {
	files := 0
	for _, f := range r.Files {
		if f.Kind == served.Script || f.Kind == served.Style {
			files++
		}
	}
	return fmt.Sprintf("found %d API spec(s) at %d path(s) tried, and %d source map(s) for %d script(s) and style(s)",
		len(p.Specs), p.Tried, len(Maps(r)), files)
}

// Findings gives one low finding per spec and per source map served.
func Findings(p Probe, r served.Result) []findings.Finding {
	var out []findings.Finding
	add := func(f findings.Finding) {
		f.Severity, f.Family = findings.Low, Family
		f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	for _, s := range p.Specs {
		where := "is served at this URL"
		if s.Embedded {
			where = "is served inside the setup script of a Swagger UI page (" + strings.TrimSuffix(s.URL, "/swagger-ui-init.js") + "/)"
		}
		add(findings.Finding{
			RuleID: "public-api-spec",
			Title:  "API spec served to anyone",
			Message: "An OpenAPI or Swagger spec " + where + ", with no login. It lists the API's routes, methods and parameters: " +
				"attack tools download such specs to choose what to test. If the API is not meant for the public, stop serving the spec in production or put it behind a login. " +
				"A spec for a public API may be served on purpose.",
			CWEs:     []string{"CWE-200"},
			Location: findings.Location{URI: s.URL},
		})
	}
	for _, m := range Maps(r) {
		add(findings.Finding{
			RuleID: "public-source-map",
			Title:  "Source map served to anyone",
			Message: "A source map is served at this URL, with no login. It gives back the app's original source code, comments included, " +
				"which shows attackers its routes and logic. Do not deploy source maps to production, or serve them only to your own team. " +
				"Secrets inside it are reported separately by " + served.ID + ".",
			CWEs:     []string{"CWE-540"},
			Location: findings.Location{URI: m.URL},
		})
	}
	return out
}
