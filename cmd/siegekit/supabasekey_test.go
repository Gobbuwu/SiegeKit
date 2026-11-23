package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type keyCall struct {
	cfg egress.Config
	key string
}

// useKeyCheck replaces the one GET that shows a project accepts the key,
// answering with err.
func useKeyCheck(t *testing.T, err error) *[]keyCall {
	t.Helper()
	var calls []keyCall
	old := keyCheck
	keyCheck = func(_ context.Context, cfg egress.Config, key string) (int, error) {
		calls = append(calls, keyCall{cfg, key})
		return 1, err
	}
	t.Cleanup(func() { keyCheck = old })
	return &calls
}

// TestScanURLSupabaseKey: an app that calls Supabase only from its server
// serves no key and does not name its backend (ADR 0061).
func TestScanURLSupabaseKey(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "abcdefghijklmnop.supabase.co": "104.18.38.10", "db.lan.test": "192.168.1.20"}
	t.Cleanup(func() { resolver = old })
	const pub = "sb_publishable_AbC123_xyz-987654"
	enc := base64.RawURLEncoding.EncodeToString
	jwt := func(payload string) string {
		return enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("not-a-real-signature"))
	}
	repo := t.TempDir()
	for name, data := range map[string]string{
		"supabase/config.toml":      `project_id = "app"`,
		"supabase/migrations/1.sql": `create table notes (id int); create table profiles (id int); insert into storage.buckets (id, name) values ('files', 'files');`,
	} {
		p := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	serverOnly := `document.querySelector("form");fetch("/api/notes")` // no Supabase URL, key or name
	scan := func(tty bool, input, envKey string, f *fakeActive, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
		if envKey != "" {
			t.Setenv(backend.KeyEnv, envKey)
		} else {
			t.Setenv(backend.KeyEnv, "unset")
			os.Unsetenv(backend.KeyEnv)
		}
		f.collected = served.Result{Files: []served.File{{Name: "001-page.html", URL: "http://localhost:3000/", Kind: served.Page}, {Name: "002-main.js", URL: "http://localhost:3000/main.js", Kind: served.Script}}, Requests: 2}
		if f.content == nil {
			f.content = map[string]string{"002-main.js": serverOnly}
		}
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	reportFiles := func() string {
		t.Helper()
		var all string
		for _, n := range []string{"report.json", "report.sarif", "report.html"} {
			b, err := os.ReadFile(filepath.Join("siegekit-report", n))
			if err != nil {
				t.Fatal(err)
			}
			all += string(b)
		}
		return all
	}
	plugin := func(id string) report.PluginResult {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatalf("report %v", err)
		}
		for _, p := range r.Plugins {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("no %s in %+v", id, r.Plugins)
		return report.PluginResult{}
	}
	auditLog := func(data string) string {
		b, _ := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
		return string(b)
	}

	// Keys that are not public, and keys that are not keys, are refused
	// before any lookup, fetch, request or audit entry; the message never
	// holds the key.
	for _, c := range []struct{ key, want string }{
		{"sb_secret_AbC123_xyz-987654", "holds a secret key (sb_secret_)"},
		{jwt(`{"role":"service_role","ref":"abcdefghijklmnop"}`), "holds a service_role key"},
		{jwt(`{"role":"authenticated"}`), `role is "authenticated"`},
		{"not-a-key", "is not a Supabase anon key"},
	} {
		for _, flag := range []string{"--backend-url", "--storage-url"} {
			f := useActive(t)
			data := useData(t)
			calls, keys, stores := useBackend(t, backend.Result{}), useKeyCheck(t, nil), useStorage(t)
			code, out := scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", c.key, f, flag, hostedBackend, "http://localhost:3000/")
			if code != exitInvalid || !strings.Contains(out, c.want) || strings.Contains(out, c.key) || len(*calls)+len(*keys)+len(*stores)+len(f.servedCfg) != 0 || auditLog(data) != "" {
				t.Errorf("%s %s: exit %d\n%s", flag, c.want, code, out)
			}
		}
	}

	// A hosted backend the scripts do not name: the host typed, then one
	// GET shows the project accepts the key, then the reads with it. The
	// key is in no report, output or audit entry.
	f := useActive(t)
	data := useData(t)
	calls, keys := useBackend(t, backend.Result{Tested: 2, Requests: 2, Empty: 2}), useKeyCheck(t, nil)
	code, out := scan(true, "abcdefghijklmnop.supabase.co\n", pub, f, "--backend-url", hostedBackend, "--source", repo, "--only", "backend-live", "http://localhost:3000/")
	if code != report.ExitClean || len(*keys) != 1 || len(*calls) != 1 || !strings.Contains(out, "Type its host name (abcdefghijklmnop.supabase.co)") ||
		!strings.Contains(out, "with the app's own public key ("+backend.KeyEnv+" when the app's scripts have none);") {
		t.Fatalf("hosted, not named: exit %d %d %d\n%s", code, len(*keys), len(*calls), out)
	}
	if k := (*keys)[0]; !k.cfg.ReadOnly || !k.cfg.VerifyTLS || k.cfg.Target.Host != "abcdefghijklmnop.supabase.co" || k.key != pub {
		t.Errorf("key check %+v", k)
	}
	if c := (*calls)[0]; c.key != pub || c.kind != backend.Supabase || !slices.Equal(c.names, []string{"notes", "profiles"}) {
		t.Errorf("call %+v", c)
	}
	if p := plugin(backend.ID); p.Status != report.Ran || p.Requests != 5 ||
		p.Input != "Supabase https://abcdefghijklmnop.supabase.co/; 0 name(s) from the app's scripts, 2 from --source; public key from "+backend.KeyEnv {
		t.Errorf("plugin %+v", p)
	}
	if strings.Contains(out+reportFiles()+auditLog(data), pub) {
		t.Error("the key was written to the output, a report or the audit log")
	}
	var e audit.Entry
	if lines := strings.Split(strings.TrimSpace(auditLog(data)), "\n"); len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &e) != nil || e.Verification != "typed backend host" {
		t.Errorf("audit %s", auditLog(data))
	}

	// The project refuses the key: nothing else is sent.
	f = useActive(t)
	useData(t)
	calls, keys = useBackend(t, backend.Result{}), useKeyCheck(t, errors.New("https://abcdefghijklmnop.supabase.co refused the key"))
	scan(true, "abcdefghijklmnop.supabase.co\n", pub, f, "--backend-url", hostedBackend, "--source", repo, "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(backend.ID); len(*keys) != 1 || len(*calls) != 0 || p.Status != report.Failed || p.Reason != "https://abcdefghijklmnop.supabase.co refused the key" || p.Requests != 3 {
		t.Errorf("refused: %d calls %+v", len(*calls), p)
	}

	// Not typed (no terminal), an anon key of another project, or no key:
	// nothing is sent to the backend, not even the key check.
	for _, c := range []struct {
		tty  bool
		key  string
		want string
	}{
		{false, pub, "No flag skips this"},
		{true, jwt(`{"role":"anon","ref":"someotherproject"}`), "the anon key in " + backend.KeyEnv + " is another project's"},
		{true, "", "does not appear in the app's start page or scripts (2 file(s) fetched), so SiegeKit cannot tell it is this app's backend; nothing was sent to it. For an app that calls Supabase only from its server, set " + backend.KeyEnv},
	} {
		f := useActive(t)
		useData(t)
		calls, keys := useBackend(t, backend.Result{}), useKeyCheck(t, nil)
		_, out := scan(c.tty, "abcdefghijklmnop.supabase.co\n", c.key, f, "--backend-url", hostedBackend, "--only", "backend-live", "http://localhost:3000/")
		if p := plugin(backend.ID); len(*calls)+len(*keys) != 0 || !strings.Contains(out+p.Reason, c.want) {
			t.Errorf("%+v: %d %d %+v", c, len(*calls), len(*keys), p)
		}
	}

	// A backend on another machine of the network, whose kind only
	// --source tells, is tested the same way.
	f = useActive(t)
	useData(t)
	calls, keys = useBackend(t, backend.Result{Tested: 2, Requests: 2, Empty: 2}), useKeyCheck(t, nil)
	scan(true, "db.lan.test\n", pub, f, "--backend-url", "http://db.lan.test:8000", "--source", repo, "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(backend.ID); len(*keys) != 1 || len(*calls) != 1 || (*keys)[0].cfg.VerifyTLS || p.Status != report.Ran ||
		!strings.HasPrefix(p.Input, "Supabase (from --source) http://db.lan.test:8000/;") {
		t.Errorf("private host: %d %d %+v", len(*keys), len(*calls), p)
	}

	// On this machine the key is used without the check (a local stack
	// may have no gateway), and the kind comes from --source.
	f = useActive(t)
	useData(t)
	calls, keys = useBackend(t, backend.Result{Tested: 2, Requests: 2, Empty: 2}), useKeyCheck(t, nil)
	code, out = scan(false, "", pub, f, "--backend-url", "http://127.0.0.1:54321", "--source", repo, "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(backend.ID); code != report.ExitClean || len(*keys) != 0 || len(*calls) != 1 || (*calls)[0].key != pub || (*calls)[0].kind != backend.Supabase ||
		p.Input != "Supabase (from --source) http://127.0.0.1:54321/; 0 name(s) from the app's scripts, 2 from --source; public key from "+backend.KeyEnv || p.Requests != 4 {
		t.Errorf("loopback: exit %d %d %d %+v\n%s", code, len(*keys), len(*calls), p, out)
	}

	// Without --source the kind stays unknown, and the reason says what
	// --source would tell.
	f = useActive(t)
	useData(t)
	calls = useBackend(t, backend.Result{})
	scan(false, "", pub, f, "--backend-url", "http://127.0.0.1:54321", "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(backend.ID); len(*calls) != 0 || p.Status != report.Failed ||
		!strings.Contains(p.Reason, "the app's scripts name neither; pass --source with the app's repository (a supabase/ directory or firebase.json tells)") {
		t.Errorf("no --source: %+v", p)
	}

	// When the scripts name the backend and have its key, theirs is used.
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": `createClient("` + hostedBackend + `","` + anonJWT() + `");s.from("profiles")`}
	calls, keys = useBackend(t, backend.Result{Tested: 2, Requests: 2, Empty: 2}), useKeyCheck(t, nil)
	scan(true, "abcdefghijklmnop.supabase.co\n", pub, f, "--backend-url", hostedBackend, "--only", "backend-live", "http://localhost:3000/")
	if p := plugin(backend.ID); len(*keys) != 0 || len(*calls) != 1 || (*calls)[0].key != anonJWT() ||
		!strings.HasSuffix(p.Input, "public key from 002-main.js ("+backend.KeyEnv+" not used: the app's scripts have a key)") {
		t.Errorf("scripts' key: %d %+v", len(*keys), p)
	}

	// storage-write: a hosted project the scripts do not name. The host and
	// the phrase are typed, the audit entry written, the key checked with a
	// read-only configuration, then the uploads; buckets from --source.
	f = useActive(t)
	data = useData(t)
	stores, keys := useStorage(t), useKeyCheck(t, nil)
	code, out = scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", pub, f, "--storage-url", hostedBackend, "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if code != report.ExitFindings || len(*keys) != 1 || len(*stores) != 1 || !(*keys)[0].cfg.ReadOnly || (*stores)[0].cfg.ReadOnly || (*stores)[0].key != pub ||
		(*stores)[0].kind != backend.SupabaseStorage || len((*stores)[0].locs) != 1 || (*stores)[0].locs[0].Bucket != "files" {
		t.Fatalf("storage: exit %d %d %+v\n%s", code, len(*keys), *stores, out)
	}
	if p := plugin(backend.StorageID); p.Status != report.Ran || p.Requests != 7 ||
		p.Input != "Supabase Storage https://abcdefghijklmnop.supabase.co; 0 bucket(s) and 0 folder(s) from the app's scripts, 1 name(s) from --source; public key from "+backend.KeyEnv {
		t.Errorf("storage plugin %+v", p)
	}
	if strings.Contains(out+reportFiles()+auditLog(data), pub) {
		t.Error("the key was written to the output, a report or the audit log")
	}

	// The project refuses the key: nothing is uploaded.
	f = useActive(t)
	useData(t)
	stores, keys = useStorage(t), useKeyCheck(t, errors.New("refused the key"))
	scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", pub, f, "--storage-url", hostedBackend, "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(backend.StorageID); len(*keys) != 1 || len(*stores) != 0 || p.Status != report.Failed || p.Reason != "nothing was uploaded: refused the key" {
		t.Errorf("storage refused: %+v", p)
	}

	// No key: the storage the scripts do not name is not contacted.
	f = useActive(t)
	useData(t)
	stores, keys = useStorage(t), useKeyCheck(t, nil)
	scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", "", f, "--storage-url", hostedBackend, "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(backend.StorageID); len(*keys)+len(*stores) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "cannot tell it is this app's storage; nothing was sent to it. For an app that calls Supabase only from its server, set "+backend.KeyEnv) {
		t.Errorf("storage no key: %+v", p)
	}

	// A local storage whose kind only --source tells: no key check.
	f = useActive(t)
	useData(t)
	stores, keys = useStorage(t), useKeyCheck(t, nil)
	scan(true, "write test files\n", pub, f, "--storage-url", "http://127.0.0.1:54321", "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(backend.StorageID); len(*keys) != 0 || len(*stores) != 1 || (*stores)[0].key != pub || p.Status != report.Ran ||
		!strings.HasPrefix(p.Input, "Supabase Storage (from --source) http://127.0.0.1:54321;") {
		t.Errorf("storage loopback: %+v", p)
	}
}
