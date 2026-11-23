package main

import (
	"bytes"
	"context"
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

type storageCall struct {
	cfg  egress.Config
	kind backend.StorageKind
	key  string
	locs []backend.Location
	left int
}

// useStorage replaces the storage write test and records its calls. Each
// call accepts every upload and deletes every file, except paths in left.
func useStorage(t *testing.T, left ...string) *[]storageCall {
	t.Helper()
	var calls []storageCall
	old := storageWrite
	storageWrite = func(_ context.Context, cfg egress.Config, kind backend.StorageKind, key string, locs []backend.Location, leftOut int) (backend.StorageResult, error) {
		calls = append(calls, storageCall{cfg, kind, key, locs, leftOut})
		r := backend.StorageResult{Kind: kind, LeftOut: leftOut, Requests: 4 * len(locs)}
		for _, l := range locs {
			o := backend.Outcome{Location: l, Written: true, Readable: true, Deleted: true, Gone: true}
			if slices.Contains(left, l.Folder) {
				o.Deleted, o.Gone, o.Left = false, false, true
			}
			r.Outcomes = append(r.Outcomes, o)
		}
		return r, nil
	}
	t.Cleanup(func() { storageWrite = old })
	return &calls
}

func TestScanURLStorage(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "abcdefghijklmnop.supabase.co": "104.18.38.10", "firebasestorage.googleapis.com": "142.250.74.10", "metadata.test": "169.254.169.254"}
	t.Cleanup(func() { resolver = old })
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "storage.rules"), []byte(`service firebase.storage { match /b/{bucket}/o { match /uploads/{f} { allow write: if true; } } }`), 0o644); err != nil {
		t.Fatal(err)
	}
	supabaseScript := `var h={"X-Client-Info":"supabase-js-web/2.49.4"};const s=createClient("` + hostedBackend + `","` + anonJWT() + `");s.storage.from("avatars").upload("public/"+id+".png",f)`
	firebaseScript := `initializeApp({projectId:"demo-app",storageBucket:"demo-app.appspot.com"});const firebase=1`
	scan := func(tty bool, input string, f *fakeActive, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
		f.collected = served.Result{Files: []served.File{{Name: "001-page.html", URL: "http://localhost:3000/", Kind: served.Page}, {Name: "002-main.js", URL: "http://localhost:3000/main.js", Kind: served.Script}}, Requests: 2}
		if f.content == nil {
			f.content = map[string]string{"002-main.js": supabaseScript}
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
			if p.ID == backend.StorageID {
				return p
			}
		}
		t.Fatalf("no %s in %+v", backend.StorageID, r.Plugins)
		return report.PluginResult{}
	}
	auditEntries := func(data string) []audit.Entry {
		t.Helper()
		b, _ := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
		var out []audit.Entry
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var e audit.Entry
			if l != "" && json.Unmarshal([]byte(l), &e) == nil {
				out = append(out, e)
			}
		}
		return out
	}

	// Mistakes and --deployed are refused before any lookup, request or
	// audit entry.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--storage-url", hostedBackend + "/storage/v1", "http://localhost:3000/"}, exitInvalid, "no path"},
		{[]string{"--storage-url", "http://firebasestorage.googleapis.com", "http://localhost:3000/"}, exitInvalid, "use https"},
		{[]string{"--storage-url", hostedBackend, "--deployed", "https://shop.example/"}, exitUsage, "only on local targets, not with --deployed"},
		{[]string{"--storage-url", hostedBackend, t.TempDir()}, exitUsage, "only apply to URL targets"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useStorage(t)
		code, out := scan(true, "write test files\n", f, c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(*calls) != 0 || len(f.servedCfg) != 0 {
			t.Errorf("%v: exit %d\n%s", c.args, code, out)
		}
		if len(auditEntries(data)) != 0 {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// Off unless asked for, and left out of --profile quick.
	f := useActive(t)
	useData(t)
	calls := useStorage(t)
	scan(true, "write test files\n", f, "--only", "storage-write,served-secrets", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Skipped || p.Cause != report.CauseNoInput || !strings.Contains(p.Reason, "pass --storage-url") {
		t.Errorf("no flag: %+v", p)
	}
	f = useActive(t)
	useData(t)
	scan(true, "write test files\n", f, "--storage-url", "http://127.0.0.1:54321", "--profile", "quick", "--skip", "zap-active", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Skipped || p.Cause != report.CauseProfile {
		t.Errorf("quick: %+v", p)
	}

	// Hosted Supabase named in the app's scripts: the host typed, then the
	// phrase after the file list; one call with the scripts' and the
	// repository's names, two audit entries, one finding per file.
	f = useActive(t)
	data := useData(t)
	calls = useStorage(t)
	code, out := scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", f, "--storage-url", hostedBackend, "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 ||
		!strings.Contains(out, "Type its host name (abcdefghijklmnop.supabase.co) to confirm it is this app's storage") ||
		!strings.Contains(out, "  avatars/siegekit-write-test-") || !strings.Contains(out, "  avatars/public/siegekit-write-test-") ||
		!strings.Contains(out, `Type "write test files" to upload them`) ||
		!strings.Contains(out, "(and https://abcdefghijklmnop.supabase.co for storage-write) is reachable") {
		t.Fatalf("hosted supabase: exit %d, %d calls\n%s", code, len(*calls), out)
	}
	c := (*calls)[0]
	if c.cfg.ReadOnly || !c.cfg.VerifyTLS || c.cfg.Target.Host != "abcdefghijklmnop.supabase.co" || c.kind != backend.SupabaseStorage || c.key != anonJWT() || len(c.locs) != 2 ||
		c.locs[0].Bucket != "avatars" || c.locs[0].Folder != "" || c.locs[1].Folder != "public/" {
		t.Errorf("call %+v", c)
	}
	if len(f.servedCfg) != 1 || !f.servedCfg[0].ReadOnly {
		t.Errorf("fetch %+v", f.servedCfg)
	}
	if es := auditEntries(data); len(es) != 2 || es[0].Target != "http://localhost:3000/" || !slices.Equal(es[0].Plugins, []string{"storage-write"}) ||
		es[1].Target != "https://abcdefghijklmnop.supabase.co/" || es[1].Verification != "typed storage host + typed phrase" || es[1].Confirmed != "abcdefghijklmnop.supabase.co" ||
		!slices.Equal(es[1].Addresses, []string{"104.18.38.10"}) || !slices.Equal(es[1].Plugins, []string{"storage-write"}) {
		t.Errorf("audit %+v", es)
	}
	if p := plugin(); p.Status != report.Ran || p.Findings != 2 || p.Requests != 10 ||
		p.Input != "Supabase Storage https://abcdefghijklmnop.supabase.co; 1 bucket(s) and 1 folder(s) from the app's scripts, 0 name(s) from --source; public key from 002-main.js" ||
		p.Result != "2 location(s) tested: 2 accepted an upload with no login, 2 read back; every test file was deleted" {
		t.Errorf("plugin %+v", p)
	}

	// Without a terminal, with the wrong host or phrase, nothing is sent to
	// the storage and no storage audit entry is written; --authorized-host
	// and --yes do not count.
	for _, c := range []struct {
		tty   bool
		input string
		extra []string
		want  string
	}{
		{false, "", nil, "No flag skips this"},
		{false, "", []string{"--authorized-host", "localhost", "--yes"}, "No flag skips this"},
		{true, "supabase.co\nwrite test files\n", nil, "the typed host name did not match"},
		{true, "abcdefghijklmnop.supabase.co\nyes\n", nil, `not confirmed: "write test files" was not typed`},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useStorage(t)
		_, out := scan(c.tty, c.input, f, append(append([]string{"--storage-url", hostedBackend, "--only", "storage-write"}, c.extra...), "http://localhost:3000/")...)
		p := plugin()
		if len(*calls) != 0 || !strings.Contains(out, c.want) || p.Status != report.Skipped || p.Cause != report.CauseNotConfirmed || len(auditEntries(data)) != 1 {
			t.Errorf("%+v: %d calls %+v\n%s", c, len(*calls), p, out)
		}
	}

	// The same host typed for backend-live is not asked again.
	f = useActive(t)
	useData(t)
	useBackend(t, backend.Result{Tested: 1, Requests: 1, Empty: 1})
	calls = useStorage(t)
	_, out = scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", f, "--backend-url", hostedBackend, "--storage-url", hostedBackend, "--only", "backend-live,storage-write", "http://localhost:3000/")
	if len(*calls) != 1 || strings.Count(out, "Type its host name") != 1 {
		t.Errorf("shared host: %d calls\n%s", len(*calls), out)
	}

	// Hosted Supabase the app's files do not name fails, with nothing sent.
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": `supabase.storage.from("x")`}
	calls = useStorage(t)
	scan(true, "abcdefghijklmnop.supabase.co\nwrite test files\n", f, "--storage-url", hostedBackend, "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "does not appear in the app's start page or scripts") {
		t.Errorf("not named: %d calls %+v", len(*calls), p)
	}

	// Hosted Firebase Storage: the bucket comes from the app's config and
	// is typed; folders come from storage.rules; a refused delete is named.
	f = useActive(t)
	data = useData(t)
	f.content = map[string]string{"002-main.js": firebaseScript}
	calls = useStorage(t, "uploads/")
	code, out = scan(true, "demo-app.appspot.com\nwrite test files\n", f, "--storage-url", "https://firebasestorage.googleapis.com", "--source", repo, "--only", "storage-write", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 || !strings.Contains(out, "Type the bucket name (demo-app.appspot.com)") ||
		!strings.Contains(out, "  gs://demo-app.appspot.com/uploads/siegekit-write-test-") ||
		!strings.Contains(out, "storage-write: 1 test file(s) may still be there; delete them:\n  gs://demo-app.appspot.com/uploads/siegekit-write-test-") {
		t.Fatalf("hosted firebase: exit %d\n%s", code, out)
	}
	if c := (*calls)[0]; c.kind != backend.FirebaseStorage || c.key != "" || len(c.locs) != 2 || c.locs[1].Folder != "uploads/" {
		t.Errorf("call %+v", c)
	}
	if es := auditEntries(data); len(es) != 2 || es[1].Verification != "typed bucket name + typed phrase" || es[1].Confirmed != "demo-app.appspot.com" {
		t.Errorf("audit %+v", es)
	}
	if p := plugin(); !strings.Contains(p.Result, "1 test file(s) may still be there, delete them: gs://demo-app.appspot.com/uploads/siegekit-write-test-") {
		t.Errorf("plugin %+v", p)
	}
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": firebaseScript}
	calls = useStorage(t)
	scan(true, "other-app.appspot.com\nwrite test files\n", f, "--storage-url", "https://firebasestorage.googleapis.com", "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Cause != report.CauseNotConfirmed || !strings.Contains(p.Reason, "the typed bucket name did not match") {
		t.Errorf("wrong bucket: %+v", p)
	}

	// A loopback emulator needs only the phrase; no bucket in the scripts
	// fails before the prompt.
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": firebaseScript}
	calls = useStorage(t)
	code, out = scan(true, "write test files\n", f, "--storage-url", "http://127.0.0.1:9199", "--only", "storage-write", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 || (*calls)[0].cfg.VerifyTLS || strings.Contains(out, "Type its host name") || strings.Contains(out, "Type the bucket name") {
		t.Errorf("loopback: exit %d\n%s", code, out)
	}
	f = useActive(t)
	useData(t)
	f.content = map[string]string{"002-main.js": `const firebase=1`}
	calls = useStorage(t)
	_, out = scan(true, "write test files\n", f, "--storage-url", "http://127.0.0.1:9199", "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "no bucket name was found") || strings.Contains(out, "Type \"write test files\"") {
		t.Errorf("no bucket: %+v\n%s", p, out)
	}

	// Addresses SiegeKit never tests fail before any request.
	f = useActive(t)
	useData(t)
	calls = useStorage(t)
	scan(true, "write test files\n", f, "--storage-url", "http://metadata.test", "--only", "storage-write", "http://localhost:3000/")
	if p := plugin(); len(*calls) != 0 || p.Status != report.Failed || !strings.Contains(p.Reason, "never tests") {
		t.Errorf("blocked: %+v", p)
	}
}
