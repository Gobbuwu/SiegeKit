package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/backend"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// backendCheck runs the backend-live check; tests replace it.
var backendCheck = backend.Check

// backendPlan is a backend that passed the address rules (ADR 0037).
type backendPlan struct {
	b     *backend.Backend
	addrs []netip.Addr
	// remote is set when the backend is not on this machine: its host must
	// appear in the app's scripts and be typed in a terminal (answer 2a).
	remote bool
	public bool
}

// planBackend resolves the backend once and applies the address rules: a
// backend on this machine follows the local target rules; any other needs
// its host typed (asked later) and named in the app's scripts. It returns
// the reason the check cannot run, if any.
func planBackend(ctx context.Context, b *backend.Backend, mode target.Mode) (*backendPlan, string) {
	addrs, err := target.Resolve(ctx, resolver, b.URL)
	if err != nil {
		return nil, fmt.Sprintf("the backend %s could not be looked up: %v", b, err)
	}
	by := map[target.Class][]string{}
	for _, a := range addrs {
		c := target.Classify(a)
		by[c] = append(by[c], a.String())
	}
	p := &backendPlan{b: b, addrs: addrs}
	switch {
	case len(by[target.Blocked]) > 0:
		return nil, fmt.Sprintf("the backend %s resolves to %s, a range SiegeKit never tests", b, strings.Join(by[target.Blocked], ", "))
	case len(by[target.Public]) > 0 && len(by[target.Public]) < len(addrs):
		return nil, fmt.Sprintf("the backend %s resolves to both public and non-public addresses (%s); SiegeKit refuses names like that", b, joinStrings(addrs))
	case len(by[target.Public]) > 0:
		p.remote, p.public = true, true
	case mode == target.Deployed:
		return nil, fmt.Sprintf("the backend %s is not a public address; with a deployed target only a hosted backend is tested", b)
	case len(by[target.Private]) > 0:
		p.remote = true
	}
	return p, ""
}

func joinStrings(addrs []netip.Addr) string {
	return strings.Join(addrStrings(addrs), ", ")
}

// collected is the start page and the files it links, fetched once for the
// served-secrets and backend-live checks (ADR 0032, ADR 0037).
type collected struct {
	work, files string
	res         served.Result
	err         error
}

// collect fetches the served files into a private directory. cfg allows
// only GET and HEAD.
func collect(ctx context.Context, cfg egress.Config, rate float64) *collected {
	c := &collected{}
	if c.work, c.err = os.MkdirTemp("", "siegekit-served-"); c.err != nil {
		return c
	}
	// The tool runs as another user when SiegeKit runs as root (ADR 0021),
	// so the directory it reads must be readable by others.
	c.files = filepath.Join(c.work, "files")
	if c.err = os.Mkdir(c.files, 0o700); c.err != nil {
		return c
	}
	if c.err = os.Chmod(c.files, 0o755); c.err != nil { // #nosec G302 -- read by the tool's user; the parent is private
		return c
	}
	c.res, c.err = servedCollect(ctx, cfg, rate, c.files)
	return c
}

func (c *collected) cleanup() {
	if c != nil && c.work != "" {
		os.RemoveAll(c.work) // #nosec G104 -- best effort: a temporary copy of the served files
	}
}

// read returns the fetched files by name.
func (c *collected) read() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, f := range c.res.Files {
		b, err := os.ReadFile(filepath.Join(c.files, f.Name)) // #nosec G304 -- names chosen by served.Collect in SiegeKit's own directory
		if err != nil {
			return nil, err
		}
		out[f.Name] = b
	}
	return out, nil
}

// runBackend reads the backend's kind, public key and table names from the
// fetched files, adds the names from --source, and sends one GET per name
// (ADR 0037). Nothing is sent to the backend when its host is not on this
// machine and the app's files do not name it.
func runBackend(ctx context.Context, p *backendPlan, c *collected, src *checks.Source, extraRequests int, pr report.PluginResult) (report.PluginResult, []findings.Finding) {
	failed := func(format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status, pr.Reason = report.Failed, fmt.Sprintf(format, a...)
		return pr, nil
	}
	pr.Requests = extraRequests
	pr.Input = p.b.String()
	if c.err != nil {
		return failed("the app's start page and scripts could not be fetched: %v", c.err)
	}
	files, err := c.read()
	if err != nil {
		return failed("%v", err)
	}
	sc := backend.ReadScripts(p.b, files)
	if p.remote && !sc.HostSeen {
		return failed("%s does not appear in the app's start page or scripts (%d file(s) fetched), so SiegeKit cannot tell it is this app's backend; nothing was sent to it", p.b.URL.Host, len(files))
	}
	if sc.Kind == "" {
		return failed("cannot tell whether %s is Supabase or Firebase: the app's scripts name neither", p.b)
	}
	fromScripts, fromSource := sc.Tables, []string(nil)
	if sc.Kind == backend.Firebase {
		fromScripts = sc.Paths
	}
	if src != nil {
		fromSource = src.Tables
		if sc.Kind == backend.Firebase {
			fromSource = nil
			for _, s := range src.Paths {
				if fp := backend.FirebasePath(s); fp != "" {
					fromSource = append(fromSource, fp)
				}
			}
		}
	}
	names, over := backend.Names(fromScripts, fromSource)
	pr.Input = fmt.Sprintf("%s %s; %d name(s) from the app's scripts", sc.Kind, p.b, len(fromScripts))
	if src != nil {
		pr.Input += fmt.Sprintf(", %d from --source", len(fromSource))
	}
	if sc.Kind == backend.Supabase && sc.Key != "" {
		pr.Input += "; public key from " + sc.KeyFile
	}
	cfg := egress.Config{Target: p.b.URL, Addrs: p.addrs, VerifyTLS: p.public, Version: version, ReadOnly: true}
	res, err := backendCheck(ctx, cfg, p.b, sc.Kind, sc.Key, names, over)
	pr.Requests += res.Requests
	if err != nil {
		return failed("%v", err)
	}
	fs := backend.Findings(p.b, res)
	pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(), len(fs)
	return pr, fs
}

// readSource reads --source before any request (answers 1a and 6a). The
// first file that is a valid OpenAPI or Swagger spec is kept for
// Schemathesis.
func readSource(dir string) (*checks.Source, *openapi.Spec, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}
	s, err := checks.ReadSource(context.Background(), dir)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range s.Specs {
		if format, err := openapi.Check(f.Data); err == nil {
			return &s, &openapi.Spec{Data: f.Data, Format: format, Source: filepath.Join(dir, filepath.FromSlash(f.Rel))}, nil
		}
	}
	return &s, nil, nil
}
