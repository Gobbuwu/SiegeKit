package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

type authzCall struct {
	cfg  egress.Config
	reqs []authz.Request
	b    http.Header
	rate float64
}

// useAuthz replaces the access-control check and records its calls.
func useAuthz(t *testing.T, res authz.Result, err error) *[]authzCall {
	t.Helper()
	var calls []authzCall
	old := authzCheck
	authzCheck = func(_ context.Context, cfg egress.Config, reqs []authz.Request, b http.Header, rate float64) (authz.Result, error) {
		calls = append(calls, authzCall{cfg, reqs, b, rate})
		return res, err
	}
	t.Cleanup(func() { authzCheck = old })
	return &calls
}

func writeHAR(t *testing.T, urls ...string) string {
	t.Helper()
	var entries []map[string]any
	for _, u := range urls {
		entries = append(entries, map[string]any{"request": map[string]any{"method": "GET", "url": u, "headers": []map[string]string{{"name": "Authorization", "value": "Bearer A"}}}})
	}
	b, err := json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "a.har")
	if err := os.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestScanURLAccessControl(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	scan := func(args ...string) (int, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	readReport := func() report.Run {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil || r.Plugins[0].ID != authz.ID {
			t.Fatalf("report %+v %v", r.Plugins, err)
		}
		return r
	}
	harFile := writeHAR(t, "http://localhost:3000/rest/basket/1", "http://localhost:3000/main.js", "http://localhost:3000/api/Users")
	leak := authz.Result{ATried: 3, Requests: 7, BTested: true, Replays: []authz.Replay{{
		Request: authz.Request{Method: "GET", Path: "/rest/basket/1"},
		A:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		B:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		None:    authz.Answer{Status: 401}, BTested: true,
	}}}

	// Mistakes are refused before any request or audit entry.
	t.Setenv(authz.SessionEnv, "Authorization: Bearer B")
	for _, c := range []struct {
		env  string
		args []string
		code int
		want string
	}{
		{"", []string{"--har-user", "a", "http://localhost:3000/"}, exitUsage, "--har-user needs --har"},
		{"", []string{"--har", harFile, t.TempDir()}, exitUsage, "only apply to URL targets"},
		{"", []string{"--har", filepath.Join(t.TempDir(), "missing.har"), "http://localhost:3000/"}, exitInvalid, "--har:"},
		{"", []string{"--har", t.TempDir(), "http://localhost:3000/"}, exitInvalid, "not a regular file"},
		{"", []string{"--har", writeHAR(t, "http://other.test/rest/basket/1"), "http://localhost:3000/"}, exitInvalid, "no GET or HEAD request"},
		{"Host: evil.test", []string{"--har", harFile, "http://localhost:3000/"}, exitInvalid, "cannot set Host"},
	} {
		if c.env != "" {
			t.Setenv(authz.SessionEnv, c.env)
		}
		f := useActive(t)
		data := useData(t)
		calls := useAuthz(t, leak, nil)
		code, out := scan(c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d, %d runs, %d checks\n%s", c.args, code, len(f.specs), len(*calls), out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
		t.Setenv(authz.SessionEnv, "Authorization: Bearer B")
	}

	// A local run: no confirmation needed (GET and HEAD only), read-only
	// configuration, B's session passed, and the leak is a high finding.
	f := useActive(t)
	data := useData(t)
	calls := useAuthz(t, leak, nil)
	code, out := scan("--har", harFile, "--har-user", "alice", "--only", "access-control,zap", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 || len(f.specs) != 1 || strings.Contains(out, "Type yes") ||
		!strings.Contains(out, "access-control       siegekit 0.0.0-dev: replay 2 GET and HEAD request(s) from a.har as account A, as account B and with no login") {
		t.Fatalf("exit %d, %d checks, %d runs\n%s", code, len(*calls), len(f.specs), out)
	}
	c := (*calls)[0]
	if !c.cfg.ReadOnly || c.cfg.VerifyTLS || c.rate != 100 || c.b.Get("Authorization") != "Bearer B" || len(c.reqs) != 3 || c.reqs[1].Path != "/api/Users" || c.reqs[0].Header.Get("Authorization") != "Bearer A" ||
		c.reqs[2].Path != "/api/items" || c.reqs[2].Header.Get("Authorization") != "Bearer A" || len(c.reqs[2].Header) != 1 {
		t.Errorf("call %+v", c)
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	var e audit.Entry
	if err != nil || json.Unmarshal(b, &e) != nil || !slices.Equal(e.Plugins, []string{"zap", "access-control"}) {
		t.Errorf("audit entry %+v %v", e, err)
	}
	r := readReport()
	p := r.Plugins[0]
	if p.Status != report.Ran || p.Requests != 7 || p.Findings != 1 || p.Input != "a.har, 2 request(s) recorded as account A; 1 route(s) from the OpenAPI spec http://localhost:3000/openapi.json; account B from SIEGEKIT_SESSION_B" ||
		p.Result != "replayed 3 request(s) (2 from the HAR file, 1 from the OpenAPI spec): 1 readable by account B, 0 readable with no login; 1 static files not replayed" {
		t.Errorf("plugin %+v", p)
	}
	var af *findings.Finding
	for i := range r.Findings {
		if r.Findings[i].RuleID == "cross-account-read" {
			af = &r.Findings[i]
		}
	}
	if af == nil || af.Severity != findings.High || af.Location.URI != "http://localhost:3000/rest/basket/1" || af.CWEs[0] != "CWE-639" {
		t.Errorf("findings %+v", r.Findings)
	}

	// Without B's session, only no login is tested; the plan says so.
	// Without a spec, only the HAR is replayed.
	os.Unsetenv(authz.SessionEnv)
	f = useActive(t)
	f.served = nil
	useData(t)
	calls = useAuthz(t, authz.Result{ATried: 2, Requests: 4}, nil)
	code, out = scan("--har", harFile, "--only", "access-control", "http://localhost:3000/")
	if code != report.ExitClean || len(*calls) != 1 || (*calls)[0].b != nil || len((*calls)[0].reqs) != 2 || !strings.Contains(out, "(SIEGEKIT_SESSION_B not set: account B is not tested)") || !strings.Contains(out, "OpenAPI spec: no OpenAPI spec was given with --openapi and none was found at") || strings.Contains(out, "tests that need one do not run") {
		t.Errorf("no B: exit %d\n%s", code, out)
	}
	if p := readReport().Plugins[0]; p.Input != "a.har, 2 request(s) recorded as account A" || !strings.Contains(p.Result, "account B not tested") {
		t.Errorf("no B: %+v", p)
	}

	// A failed check makes the run incomplete; --profile quick runs it.
	useActive(t)
	useData(t)
	useAuthz(t, authz.Result{}, errors.New("boom"))
	if code, _ := scan("--har", harFile, "--only", "access-control", "http://localhost:3000/"); code != report.ExitIncomplete || readReport().Plugins[0].Status != report.Failed {
		t.Errorf("failed check: exit %d %+v", code, readReport().Plugins[0])
	}
	useActive(t)
	useData(t)
	calls = useAuthz(t, authz.Result{ATried: 2}, nil)
	if code, out := scan("--har", harFile, "--profile", "quick", "--only", "access-control", "http://localhost:3000/"); code != report.ExitClean || len(*calls) != 1 {
		t.Errorf("quick: exit %d\n%s", code, out)
	}

	// Not on Linux: failed, nothing sent.
	useActive(t)
	useData(t)
	calls = useAuthz(t, leak, nil)
	hostOS = "darwin"
	code, _ = scan("--har", harFile, "--only", "access-control", "http://localhost:3000/")
	hostOS = "linux"
	if len(*calls) != 0 || readReport().Plugins[0].Status != report.Failed {
		t.Errorf("darwin: exit %d %+v", code, readReport().Plugins[0])
	}

	// Deployed targets run it too (answer 3a), with TLS checked.
	useActive(t)
	data = useData(t)
	calls = useAuthz(t, authz.Result{ATried: 1}, nil)
	tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	useProver(t, &fakeProver{published: map[string]string{"shop.example": verify.Value(tok)}})
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("shop.example\n")
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	code, out = scan("--deployed", "--har", writeHAR(t, "https://shop.example/api/me"), "--only", "access-control", "https://shop.example/")
	if code != exitOK || len(*calls) != 1 || !(*calls)[0].cfg.VerifyTLS || !(*calls)[0].cfg.ReadOnly || (*calls)[0].rate != 10 {
		t.Errorf("deployed: exit %d %+v\n%s", code, *calls, out)
	}
}
