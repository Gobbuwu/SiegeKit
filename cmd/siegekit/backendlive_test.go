package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/backend"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/served"
)

type backendCall struct {
	cfg   egress.Config
	kind  backend.Kind
	key   string
	names []string
}

// useBackend replaces the backend check and records its calls.
func useBackend(t *testing.T, res backend.Result) *[]backendCall {
	t.Helper()
	var calls []backendCall
	old := backendCheck
	backendCheck = func(_ context.Context, cfg egress.Config, _ *backend.Backend, kind backend.Kind, key string, names []string, _ int) (backend.Result, error) {
		calls = append(calls, backendCall{cfg, kind, key, names})
		res.Kind = kind
		return res, nil
	}
	t.Cleanup(func() { backendCheck = old })
	return &calls
}

const hostedBackend = "https://abcdefghijklmnop.supabase.co"

func anonJWT() string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(`{"role":"anon","ref":"abcdefghijklmnop"}`)) + "." + enc([]byte("not-a-real-signature"))
}

func TestScanURLBackend(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "abcdefghijklmnop.supabase.co": "104.18.38.10", "metadata.test": "169.254.169.254", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "supabase", "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "supabase", "migrations", "1.sql"), []byte("create table private_notes (id int);"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "openapi.json"), []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `const s=createClient("` + hostedBackend + `","` + anonJWT() + `");s.from("profiles").select()`
	scan := func(tty bool, input string, f *fakeActive, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
		f.collected = served.Result{Files: []served.File{{Name: "001-page.html", URL: "http://localhost:3000/", Kind: served.Page}, {Name: "002-main.js", URL: "http://localhost:3000/main.js", Kind: served.Script}}, Requests: 2}
		if f.content == nil {
			f.content = map[string]string{"002-main.js": script}
		}
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	plugin := func() report.PluginResult {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatalf("report %v", err)
		}
		for _, p := range r.Plugins {
			if p.ID == backend.ID {
				return p
			}
		}
		t.Fatalf("no %s in %+v", backend.ID, r.Plugins)
		return report.PluginResult{}
	}

	// Mistakes are refused before any lookup, request or audit entry.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--backend-url", hostedBackend + "/rest/v1", "http://localhost:3000/"}, exitInvalid, "no path"},
		{[]string{"--backend-url", "http://abcdefghijklmnop.supabase.co", "http://localhost:3000/"}, exitInvalid, "use https"},
		{[]string{"--source", filepath.Join(repo, "openapi.json"), "http://localhost:3000/"}, exitInvalid, "not a directory"},
		{[]string{"--source", filepath.Join(repo, "missing"), "http://localhost:3000/"}, exitInvalid, "--source"},
		{[]string{"--backend-url", hostedBackend, t.TempDir()}, exitUsage, "only apply to URL targets"},
		{[]string{"--source", repo, t.TempDir()}, exitUsage, "only apply to URL targets"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useBackend(t, backend.Result{})
		code, out := scan(false, "", f, c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d\n%s", c.args, code, out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// A hosted backend named in the app's scripts, its host typed: one call
	// with the scripts' and the repository's tables, a finding, two audit
	// entries.
	f := useActive(t)
	data := useData(t)
	calls := useBackend(t, backend.Result{Tested: 2, Requests: 2, Readable: []backend.Readable{{Name: "profiles", Columns: []string{"email", "id"}}}})
	code, out := scan(true, "abcdefghijklmnop.supabase.co\n", f, "--backend-url", hostedBackend, "--source", repo, "--only", "backend-live", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 || !strings.Contains(out, "Type its host name (abcdefghijklmnop.supabase.co)") ||
		!strings.Contains(out, "backend-live         siegekit 0.0.0-dev: one GET (at most one row) per table or path at https://abcdefghijklmnop.supabase.co/ (104.18.38.10), with the app's own public key;") ||
		!strings.Contains(out, "(and https://abcdefghijklmnop.supabase.co for backend-live) is reachable") {
		t.Fatalf("exit %d, %d calls\n%s", code, len(*calls), out)
	}
	if c := (*calls)[0]; !c.cfg.ReadOnly || !c.cfg.VerifyTLS || c.cfg.Target.Host != "abcdefghijklmnop.supabase.co" || c.kind != backend.Supabase || c.key != anonJWT() || !slices.Equal(c.names, []string{"private_notes", "profiles"}) {
		t.Errorf("call %+v", c)
	}
	if len(f.servedCfg) != 1 || !f.servedCfg[0].ReadOnly {
		t.Errorf("fetch %+v", f.servedCfg)
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var e1, e2 audit.Entry
	if err != nil || len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &e1) != nil || json.Unmarshal([]byte(lines[1]), &e2) != nil ||
		e1.Target != "http://localhost:3000/" || !slices.Equal(e1.Plugins, []string{"backend-live"}) ||
		e2.Target != "https://abcdefghijklmnop.supabase.co/" || e2.Verification != "typed backend host" || e2.Confirmed != "abcdefghijklmnop.supabase.co" || !slices.Equal(e2.Addresses, []string{"104.18.38.10"}) {
		t.Errorf("audit %s %v", b, err)
	}
	if p := plugin(); p.Status != report.Ran || p.Findings != 1 || p.Requests != 4 || p.Input != "Supabase https://abcdefghijklmnop.supabase.co/; 1 name(s) from the app's scripts, 1 from --source; public key from 002-main.js" {
		t.Errorf("plugin %+v", p)
	}

	// Without a terminal, or with the wrong host typed, nothing is sent to
	// the backend; --authorized-host does not count.
	for _, c := range []struct {
		tty   bool
		input string
		extra []string
		want  string
	}{
		{false, "", nil, "No flag skips this"},
		{false, "", []string{"--authorized-host", "abcdefghijklmnop.supabase.co"}, "does not match the target host"},
		{false, "", []string{"--authorized-host", "localhost"}, "No flag skips this"},
		{true, "supabase.co\n", nil, "the typed host name did not match"},
	} {
		f := useActive(t)
		useData(t)
		calls := useBackend(t, backend.Result{})
		_, out := scan(c.tty, c.input, f, append(append([]string{"--backend-url", hostedBackend, "--only", "backend-live"}, c.extra...), "http://localhost:3000/")...)
		if len(*calls) != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%+v: %d calls\n%s", c, len(*calls), out)
		}
	}

	// A hosted backend the app's files do not name fails, with nothing sent.
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": `no backend here`}
	calls = useBackend(t, backend.Result{})
	scan(true, "abcdefghijklmnop.supabase.co\n", f, "--backend-url", hostedBackend, "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "does not appear in the app's start page or scripts") {
		t.Errorf("not named: %d calls %+v", len(*calls), p)
	}

	// A backend on this machine follows the local target rules: no typing,
	// and it need not be named in the scripts.
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": `createClient("http://localhost:54321","` + anonJWT() + `");x.from("todos");supabase`}
	calls = useBackend(t, backend.Result{Tested: 1, Requests: 1, Empty: 1})
	code, out = scan(false, "", f, "--backend-url", "http://127.0.0.1:54321", "--only", "backend-live,served-secrets", "http://localhost:3000/")
	if code != report.ExitClean || len(*calls) != 1 || (*calls)[0].cfg.VerifyTLS || strings.Contains(out, "Type its host name") || !slices.Equal((*calls)[0].names, []string{"todos"}) || len(f.servedCfg) != 1 ||
		!strings.Contains(out, "with the app's own public key for Supabase, with no login for Firebase;") {
		t.Errorf("loopback: exit %d %+v\n%s", code, *calls, out)
	}
	if p := plugin(); p.Status != report.Ran || p.Requests != 1 || p.Result != "1 tables tested: 0 readable, 1 empty or protected by row-level security" {
		t.Errorf("loopback plugin %+v", p)
	}

	// Addresses SiegeKit never tests, and a loopback backend with a
	// deployed target, fail before any request.
	f = useActive(t)
	useData(t)
	calls = useBackend(t, backend.Result{})
	scan(false, "", f, "--backend-url", "http://metadata.test", "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "never tests") {
		t.Errorf("blocked: %+v", p)
	}

	// The repository's spec is used when the app serves none, without
	// probing the default paths.
	f = useActive(t)
	useData(t)
	f.served = map[string]string{}
	useBackend(t, backend.Result{})
	code, out = scan(false, "", f, "--source", repo, "--authorized-host", "localhost", "--only", "schemathesis", "http://localhost:3000/")
	if len(f.got) != 0 || !strings.Contains(out, "OpenAPI spec: "+filepath.Join(repo, "openapi.json")) || len(f.specs) != 1 {
		t.Errorf("source spec: exit %d, probes %v\n%s", code, f.got, out)
	}
}
