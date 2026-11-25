package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/wordlists"
)

const zapReport = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP","rules":[{"id":"10021","name":"X-Content-Type-Options Header Missing",
"relationships":[{"target":{"id":"693","toolComponent":{"name":"CWE"}}}]}]}},
"results":[{"ruleId":"10021","level":"note","message":{"text":"missing"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"http://app.test:8000/"},"region":{"startLine":1}}}]}]}]}`

func urlOpts(t *testing.T) URLOptions {
	t.Helper()
	u, err := target.Parse("http://app.test:8000/")
	if err != nil {
		t.Fatal(err)
	}
	return URLOptions{Version: "test", Target: u, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Limits: LocalLimits}
}

func TestRunURL(t *testing.T) {
	zap, active := builtin(t, "zap"), builtin(t, "zap-active")
	var configs []map[string]any
	result := func(res *ActiveResult) ActiveRunner {
		return func(_ context.Context, sp sandbox.Spec, c egress.Config) (*ActiveResult, error) {
			b, err := os.ReadFile(sp.ConfigFile)
			if err != nil {
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			configs = append(configs, m)
			if c.Target.String() != "http://app.test:8000/" || c.MaxServerErrors != LocalLimits.MaxServerErrors || c.ReadOnly {
				t.Errorf("egress config %+v", c)
			}
			os.WriteFile(filepath.Join(sp.OutDir, "zap.json"), []byte(zapReport), 0o600)
			return res, nil
		}
	}
	ok := &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 5, Refused: 1}}
	r, err := RunURL(context.Background(), result(ok), []*manifest.Manifest{zap, active}, urlOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Target != "http://app.test:8000/" || r.Mode != "local" || len(r.Plugins) != 2 || len(r.Findings) != 1 {
		t.Fatalf("run %+v", r)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Ran || p.Requests != 5 || p.Refused != 1 || p.Findings != 1 {
			t.Errorf("plugin %+v", p)
		}
	}
	if f := r.Findings[0]; f.Location.URI != "http://app.test:8000/" || len(f.CWEs) != 1 || f.CWEs[0] != "CWE-693" || len(f.Sources) != 2 {
		t.Errorf("finding %+v", f)
	}
	// The configuration names the target as JSON strings.
	ctx := configs[0]["env"].(map[string]any)["contexts"].([]any)[0].(map[string]any)
	if ctx["urls"].([]any)[0] != "http://app.test:8000/" || ctx["includePaths"].([]any)[0] != `http://app\.test:8000/.*` {
		t.Errorf("context %v", ctx)
	}

	// Deployed: the attack scan is skipped, and the proxy checks TLS.
	opt := urlOpts(t)
	opt.Deployed, opt.Limits = true, DeployedLimits
	r, err = RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, c egress.Config) (*ActiveResult, error) {
		if !c.VerifyTLS || c.Rate != DeployedLimits.Rate || !c.ReadOnly {
			t.Errorf("deployed egress config %+v", c)
		}
		os.WriteFile(filepath.Join(sp.OutDir, "zap.json"), []byte(zapReport), 0o600)
		return ok, nil
	}, []*manifest.Manifest{zap, active}, opt)
	if err != nil || r.Mode != "deployed" || r.Plugins[0].Status != report.Ran || r.Plugins[1].Status != report.Skipped || !strings.Contains(r.Plugins[1].Reason, "only on local targets") {
		t.Errorf("deployed: %+v %v", r, err)
	}

	for name, tc := range map[string]struct {
		res  *ActiveResult
		err  error
		want report.Status
		why  string
	}{
		"stopped":     {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Failed, ExitCode: -1}, Stats: egress.Stats{Requests: 9}, Stopped: "3 server errors in a row"}, nil, report.Failed, "stopped by SiegeKit: 3 server errors"},
		"timed out":   {&ActiveResult{Result: &sandbox.Result{Status: sandbox.TimedOut, Stop: sandbox.StopTimeLimit, StopReason: "stopped after 30 seconds, its time limit"}, Stats: egress.Stats{Requests: 9}}, nil, report.TimedOut, "stopped after"},
		"exit code":   {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed, ExitCode: 1, Stderr: "Automation plan failures"}, Stats: egress.Stats{Requests: 9}}, nil, report.Failed, "Automation plan failures"},
		"no requests": {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}}, nil, report.Failed, "answered no request"},
		"relay error": {nil, errors.New("start relay: no image"), report.Failed, "start relay"},
	} {
		r, err := RunURL(context.Background(), func(context.Context, sandbox.Spec, egress.Config) (*ActiveResult, error) {
			return tc.res, tc.err
		}, []*manifest.Manifest{zap}, urlOpts(t))
		if err != nil || r.Plugins[0].Status != tc.want || !strings.Contains(r.Plugins[0].Reason, tc.why) || len(r.Findings) != 0 {
			t.Errorf("%s: %+v %v", name, r.Plugins, err)
		}
	}

	// Plugins missing a dependency are reported, not run.
	opt = urlOpts(t)
	opt.Unavailable = map[string]Unavailable{"zap": {Status: report.Skipped, Reason: "you declined"}}
	r, err = RunURL(context.Background(), nil, []*manifest.Manifest{zap}, opt)
	if err != nil || r.Plugins[0].Status != report.Skipped {
		t.Errorf("unavailable: %+v %v", r, err)
	}
	if _, err := RunURL(context.Background(), nil, nil, URLOptions{}); err == nil {
		t.Error("no target accepted")
	}
}

func TestConfigForKeepsTargetAString(t *testing.T) {
	in := map[string]any{"a": []any{"{target}", map[string]any{"b": "x{target-regex}y"}}, "n": 3.0, "t": true}
	b, err := json.Marshal(configFor(in, `http://h/"}],"x":{"`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out["a"].([]any)[0] != `http://h/"}],"x":{"` || out["n"] != 3.0 {
		t.Errorf("config %s", b)
	}
	if got := out["a"].([]any)[1].(map[string]any)["b"]; got != `xhttp://h/"\}\],"x":\{"y` {
		t.Errorf("regex %q", got)
	}
}

func TestSkipReason(t *testing.T) {
	zap, active, gitleaks := builtin(t, "zap"), builtin(t, "zap-active"), builtin(t, "gitleaks")
	if SkipReason(zap, false) != "" || SkipReason(zap, true) != "" || SkipReason(active, false) != "" {
		t.Error("runnable plugin skipped")
	}
	if !strings.Contains(SkipReason(active, true), "only on local targets") || !strings.Contains(SkipReason(gitleaks, false), "only active plugins") {
		t.Error("missing skip reason")
	}
	destructive := *zap
	d := true
	destructive.Destructive = &d
	if !strings.Contains(SkipReason(&destructive, true), "does not run on deployed targets") {
		t.Error("destructive plugin not skipped on a deployed target")
	}
}

// installed is a files root holding m's pinned files, marked installed.
func installed(t *testing.T, m *manifest.Manifest) string {
	t.Helper()
	root := t.TempDir()
	for _, a := range FilesFor(m) {
		if err := os.MkdirAll(files.Dir(root, a), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(files.Dir(root, a)+".ok", nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestWordlist checks that a URL plugin gets the shipped list for the
// target's mode, mounted read-only at {wordlist} (ADR 0027).
func TestWordlist(t *testing.T) {
	m := builtin(t, "ffuf")
	root := installed(t, m)
	for _, deployed := range []bool{false, true} {
		opt := urlOpts(t)
		opt.FilesRoot, opt.Deployed = root, deployed
		want, _ := wordlists.Get("seclists-common.txt")
		if deployed {
			opt.Limits = DeployedLimits
			want, _ = wordlists.Get("deployed.txt")
		}
		var got []byte
		r, err := RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, _ egress.Config) (*ActiveResult, error) {
			if !slices.Contains(sp.Args, WordlistMount+"/paths.txt") || !slices.Contains(sp.Args, "http://app.test:8000/FUZZ") {
				t.Errorf("args %v", sp.Args)
			}
			for _, f := range sp.Files {
				if f.Mount == WordlistMount {
					got, _ = os.ReadFile(filepath.Join(f.Host, "paths.txt"))
				}
			}
			os.WriteFile(filepath.Join(sp.OutDir, "ffuf.json"), []byte(`{"results":[{"status":200,"length":3,"url":"http://app.test:8000/.env"}]}`), 0o600)
			return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 1}}, nil
		}, []*manifest.Manifest{m}, opt)
		if err != nil || r.Plugins[0].Status != report.Ran || len(r.Findings) != 1 {
			t.Errorf("deployed %v: %+v %v", deployed, r, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("deployed %v: mounted list of %d bytes, want %d", deployed, len(got), len(want))
		}
	}
}

// TestOpenAPISpec checks that Schemathesis is skipped without a spec, gets
// the spec mounted read-only and the target's origin, that its exit code 1
// (failures found) is read as a result while others are failures, and that
// finding locations carry the spec's base path (ADR 0028).
func TestOpenAPISpec(t *testing.T) {
	m := builtin(t, "schemathesis")
	never := func(context.Context, sandbox.Spec, egress.Config) (*ActiveResult, error) {
		t.Fatal("ran without a spec")
		return nil, nil
	}
	opt := urlOpts(t)
	opt.NoOpenAPI = "none found at the default paths"
	r, err := RunURL(context.Background(), never, []*manifest.Manifest{m}, opt)
	if err != nil || r.Plugins[0].Status != report.Skipped || r.Plugins[0].Reason != opt.NoOpenAPI {
		t.Fatalf("%+v %v", r, err)
	}
	opt.OpenAPI = &openapi.Spec{Data: []byte(`{"openapi":"3.0.3","servers":[{"url":"/api/"}],"paths":{}}`), Format: "json", Source: "http://app.test:8000/openapi.json"}
	const rep = `{"complete":true,"operations":{"selected":1,"tested":1},"errors":[],"failures":[{"code":"ST101","title":"Server error","operations":["GET /items/{id}"]}]}`
	for _, exit := range []int{0, 1, 2} {
		var got []byte
		r, err := RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, _ egress.Config) (*ActiveResult, error) {
			if !slices.Contains(sp.Args, OpenAPIMount+"/spec.json") || !slices.Contains(sp.Args, "http://app.test:8000") {
				t.Errorf("args %v", sp.Args)
			}
			for _, f := range sp.Files {
				if f.Mount == OpenAPIMount {
					got, _ = os.ReadFile(filepath.Join(f.Host, "spec.json"))
				}
			}
			os.WriteFile(filepath.Join(sp.OutDir, "schemathesis.json"), []byte(rep), 0o600)
			return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed, ExitCode: exit}, Stats: egress.Stats{Requests: 1}}, nil
		}, []*manifest.Manifest{m}, opt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, opt.OpenAPI.Data) {
			t.Errorf("mounted spec %q", got)
		}
		p := r.Plugins[0]
		if exit == 2 {
			if p.Status != report.Failed || !strings.Contains(p.Reason, "exited with code 2") {
				t.Errorf("exit 2: %+v", p)
			}
			continue
		}
		if p.Status != report.Ran || p.Input != "OpenAPI spec http://app.test:8000/openapi.json" || len(r.Findings) != 1 || r.Findings[0].Location.URI != "http://app.test:8000/api/items/{id}" {
			t.Errorf("exit %d: %+v %+v", exit, p, r.Findings)
		}
	}
}

// TestRecordedRequests checks ADR 0047: zap-active gets the recorded
// requests as a HAR file, mounted read-only, and an import job before its
// spider; zap and runs without recorded requests are unchanged.
func TestRecordedRequests(t *testing.T) {
	za, zp := builtin(t, "zap-active"), builtin(t, "zap")
	if !za.Run.Recorded || zp.Run.Recorded {
		t.Fatalf("recordedRequests: zap-active %v, zap %v", za.Run.Recorded, zp.Run.Recorded)
	}
	opt := urlOpts(t)
	opt.RecordedFrom = "a.har"
	// A body ZAP's ISO-8859-1 import would change, and a GET without one
	// (ADR 0065).
	const name = `{"name":"é€😀"}`
	opt.Recorded = []authz.RecordedRequest{
		{Method: "POST", URL: "http://app.test:8000/api/order", Header: http.Header{"Cookie": {"s=A"}, "Content-Type": {"application/xml"}}, MimeType: "application/xml", Body: "<order/>"},
		{Method: "PUT", URL: "http://app.test:8000/api/name", Header: http.Header{"Content-Type": {"application/json"}}, MimeType: "application/json", Body: name},
		{Method: "GET", URL: "http://app.test:8000/api/me", Header: http.Header{"Cookie": {"s=A"}}},
	}
	type seen struct {
		jobs []string
		har  []byte
	}
	got := map[string]seen{}
	run := func(_ context.Context, sp sandbox.Spec, _ egress.Config) (*ActiveResult, error) {
		var s seen
		b, err := os.ReadFile(sp.ConfigFile)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Jobs []struct {
				Type       string         `json:"type"`
				Parameters map[string]any `json:"parameters"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		for _, j := range c.Jobs {
			s.jobs = append(s.jobs, j.Type)
			if j.Type == "import" && (j.Parameters["type"] != "har" || j.Parameters["fileName"] != RecordedMount+"/requests.har") {
				t.Errorf("import job %v", j.Parameters)
			}
		}
		for _, f := range sp.Files {
			if f.Mount == RecordedMount {
				s.har, _ = os.ReadFile(filepath.Join(f.Host, "requests.har"))
			}
		}
		got[sp.Image+" "+strings.Join(s.jobs, ",")] = s
		os.WriteFile(filepath.Join(sp.OutDir, "zap.json"), []byte(zapReport), 0o600)
		return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 1}}, nil
	}
	r, err := RunURL(context.Background(), run, []*manifest.Manifest{zp, za}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var withImport, without int
	for k, s := range got {
		switch {
		case strings.HasSuffix(k, "passiveScan-config,import,spider,activeScan,report"):
			withImport++
			var h struct {
				Log struct {
					Entries []struct {
						Request struct {
							Method, URL string
							Headers     []struct{ Name, Value string }
							PostData    struct{ MimeType, Text string }
						}
					}
				}
			}
			if err := json.Unmarshal(s.har, &h); err != nil || len(h.Log.Entries) != 3 {
				t.Fatalf("HAR %s %v", s.har, err)
			}
			e := h.Log.Entries[0].Request
			if e.Method != "POST" || e.URL != "http://app.test:8000/api/order" || e.PostData.Text != "<order/>" || e.PostData.MimeType != "application/xml" ||
				!slices.Contains(e.Headers, struct{ Name, Value string }{"Cookie", "s=A"}) {
				t.Errorf("entry %+v", e)
			}
			// ZAP sends the headers as given and the text in ISO-8859-1
			// (ADR 0065): each request with a body needs its one
			// Content-Length, and the text's characters must be the
			// body's bytes.
			for i, want := range []string{"<order/>", name, ""} {
				e := h.Log.Entries[i].Request
				var lengths []string
				for _, hd := range e.Headers {
					if strings.EqualFold(hd.Name, "Content-Length") {
						lengths = append(lengths, hd.Value)
					}
				}
				sent := make([]byte, 0, len(e.PostData.Text))
				for _, c := range e.PostData.Text {
					if c > 0xff {
						t.Fatalf("entry %d: %q is not one byte in ISO-8859-1", i, c)
					}
					sent = append(sent, byte(c))
				}
				if string(sent) != want {
					t.Errorf("entry %d: ZAP would send %q, want %q", i, sent, want)
				}
				if wantLen := []string{strconv.Itoa(len(want))}; want == "" && lengths != nil || want != "" && !slices.Equal(lengths, wantLen) {
					t.Errorf("entry %d: Content-Length %v for a %d-byte body", i, lengths, len(want))
				}
			}
		case !strings.Contains(k, "import"):
			without++
			if s.har != nil {
				t.Errorf("%s got the recorded requests", k)
			}
		}
	}
	if withImport != 1 || without != 1 {
		t.Errorf("runs %v", slices.Collect(maps.Keys(got)))
	}
	if p := r.Plugins[1]; p.ID != "zap-active" || p.Input != "3 recorded request(s) from a.har" || r.Plugins[0].Input != "" {
		t.Errorf("plugins %+v", r.Plugins)
	}

	// No recorded requests: no import job, no mount.
	got = map[string]seen{}
	opt.Recorded = nil
	if _, err := RunURL(context.Background(), run, []*manifest.Manifest{za}, opt); err != nil {
		t.Fatal(err)
	}
	for k, s := range got {
		if strings.Contains(k, "import") || s.har != nil {
			t.Errorf("without recorded requests: %s", k)
		}
	}
}

// startPage is a target's start page whose answer a test switches between
// 200 and a 25,000-byte 403 block page (ADR 0071).
type startPage struct {
	srv     *httptest.Server
	blocked atomic.Bool
	fetches atomic.Int32
}

func newStartPage(t *testing.T) (*startPage, *egress.Watch) {
	t.Helper()
	s := &startPage{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		w.Header().Set("Content-Type", "text/html")
		if s.blocked.Load() {
			w.WriteHeader(http.StatusForbidden)
			w.Write(bytes.Repeat([]byte("c"), 25000))
			return
		}
		w.Write([]byte("the app"))
	}))
	t.Cleanup(s.srv.Close)
	port := s.srv.Listener.Addr().(*net.TCPAddr).Port
	u, err := target.Parse("http://app.test:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	return s, egress.NewWatch(egress.Config{Target: u, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"})
}

// TestRunURLHostBlocked checks how a plugin ends when the host stops
// serving the app (ADR 0071): stopped by the proxy (D3) or found after the
// plugin (D1), its findings read from block-page answers are dropped (F2)
// and the others kept; a plugin that starts while the host still blocks
// is not run.
func TestRunURLHostBlocked(t *testing.T) {
	ffufM, zap := builtin(t, "ffuf"), builtin(t, "zap")
	ffufReport := `{"results":[
{"url":"http://app.test:8000/admin","status":200,"length":1234,"content-type":"text/html"},
{"url":"http://app.test:8000/a","status":403,"length":25004,"content-type":"text/html"},
{"url":"http://app.test:8000/b","status":403,"length":24996,"content-type":"text/html"},
{"url":"http://app.test:8000/forbidden","status":403,"length":120,"content-type":"text/html"}]}`
	block := &egress.Block{Page: egress.Shape{Status: 403, Type: "text/html", Len: 25000}, Reason: "the host stopped serving the app: 10 answers in a row and the start page were the same page"}
	for name, tc := range map[string]struct {
		res     *ActiveResult
		blockIn bool // the start page turns into the block page during the run
		reason  string
	}{
		"proxy":              {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Failed, ExitCode: -1}, Stats: egress.Stats{Requests: 1010}, Stopped: block.Reason, Block: block}, false, "10 answers in a row"},
		"after":              {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 4758}}, true, "during this check: after it, the start page answered 403 (text/html, 25000 bytes)"},
		"after a time limit": {&ActiveResult{Result: &sandbox.Result{Status: sandbox.TimedOut, Stop: sandbox.StopTimeLimit, StopReason: "stopped after 600 seconds, its time limit"}, Stats: egress.Stats{Requests: 4758}}, true, "the tool was also cut short: stopped after 600 seconds"},
	} {
		sp, w := newStartPage(t)
		opt := urlOpts(t)
		opt.Watch, opt.FilesRoot = w, installed(t, ffufM)
		ran := 0
		r, err := RunURL(context.Background(), func(_ context.Context, s sandbox.Spec, c egress.Config) (*ActiveResult, error) {
			ran++
			if c.Watch == nil || c.Watch.Block() != nil {
				t.Errorf("%s: plugin config watch %v", name, c.Watch)
			}
			os.WriteFile(filepath.Join(s.OutDir, "ffuf.json"), []byte(ffufReport), 0o600)
			sp.blocked.Store(tc.blockIn || tc.res.Block != nil)
			return tc.res, nil
		}, []*manifest.Manifest{ffufM, zap}, opt)
		if err != nil {
			t.Fatal(err)
		}
		p := r.Plugins[0]
		if p.Status != report.Failed || p.Stop != report.StopHostBlocked || !strings.Contains(p.Reason, tc.reason) || !strings.Contains(p.Reason, "; 2 finding(s) read from answers like the block page dropped; the 2 finding(s) reported before the stop are kept") || p.Findings != 2 {
			t.Errorf("%s: %+v", name, p)
		}
		var uris []string
		for _, f := range r.Findings {
			uris = append(uris, f.Location.URI)
		}
		slices.Sort(uris)
		if !slices.Equal(uris, []string{"http://app.test:8000/admin", "http://app.test:8000/forbidden"}) {
			t.Errorf("%s: findings %v", name, uris)
		}
		// ZAP starts while the host still blocks: not run.
		z := r.Plugins[1]
		if ran != 1 || z.Status != report.Failed || z.Stop != report.StopHostBlocked || z.Requests != 0 || !strings.Contains(z.Reason, "stopped by SiegeKit: the host stopped serving the app before this check: the start page answered 403") {
			t.Errorf("%s: %d runs, zap %+v", name, ran, z)
		}
		want := int32(3) // before ffuf, after it, before ZAP
		if tc.res.Block != nil {
			want = 2 // the proxy's stop needs no fetch after
		}
		if n := sp.fetches.Load(); n != want {
			t.Errorf("%s: %d start-page fetches, want %d", name, n, want)
		}
	}

	// No block: both run, ffuf keeps all four findings.
	sp, w := newStartPage(t)
	opt := urlOpts(t)
	opt.Watch, opt.FilesRoot = w, installed(t, ffufM)
	r, err := RunURL(context.Background(), func(_ context.Context, s sandbox.Spec, c egress.Config) (*ActiveResult, error) {
		os.WriteFile(filepath.Join(s.OutDir, "ffuf.json"), []byte(ffufReport), 0o600)
		os.WriteFile(filepath.Join(s.OutDir, "zap.json"), []byte(zapReport), 0o600)
		return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 5}}, nil
	}, []*manifest.Manifest{ffufM, zap}, opt)
	if err != nil || r.Plugins[0].Status != report.Ran || r.Plugins[0].Findings != 4 || r.Plugins[1].Status != report.Ran || sp.fetches.Load() != 4 {
		t.Errorf("no block: %+v %v, %d fetches", r.Plugins, err, sp.fetches.Load())
	}

	// A plugin whose input was cut short keeps the stop (the spec probe).
	opt = urlOpts(t)
	opt.Unavailable = map[string]Unavailable{"zap": {Status: report.Failed, Stop: report.StopHostBlocked, Reason: "stopped by SiegeKit: x"}}
	r, err = RunURL(context.Background(), nil, []*manifest.Manifest{zap}, opt)
	if err != nil || r.Plugins[0].Stop != report.StopHostBlocked {
		t.Errorf("unavailable: %+v %v", r.Plugins, err)
	}
}

// TestHostBlockedAccessControl checks F2 on access-control's findings
// (ADR 0071): a finding is dropped when any answer it was read from was the
// block page, as when the no-login replay of /rest/memories/ got the block
// page and the read looked refused (measured on Juice Shop, 2026-11-25);
// the findings read from the app are kept.
func TestHostBlockedAccessControl(t *testing.T) {
	page := bytes.Repeat([]byte("c"), 24987)
	ok := authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)}
	res := authz.Result{BTested: true, CTested: true, Replays: []authz.Replay{
		{Request: authz.Request{Method: "GET", Path: "/rest/basket/6"}, A: ok, B: ok, C: ok, None: authz.Answer{Status: 401, Body: []byte("no")}, BTested: true, CTested: true},
		{Request: authz.Request{Method: "GET", Path: "/rest/memories/"}, A: ok, B: ok, C: ok, None: authz.Answer{Status: 403, Body: page[:24990-7]}, BTested: true, CTested: true},
	}}
	fs := authz.Findings("http://app.test", res, "")
	if len(fs) != 2 {
		t.Fatalf("findings %+v", fs)
	}
	b := &egress.Block{Page: egress.Shape{Status: 403, Type: "text/html", Len: 24987}, Reason: "the host stopped serving the app"}
	pr, kept := HostBlocked(report.PluginResult{ID: authz.ID}, b, fs)
	if len(kept) != 1 || kept[0].Location.URI != "http://app.test/rest/basket/6" || pr.Findings != 1 || !strings.Contains(pr.Reason, "1 finding(s) read from answers like the block page dropped") {
		t.Errorf("%+v %+v", pr, kept)
	}
}
