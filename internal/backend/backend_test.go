package backend

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// jwt builds a token at run time, so this file holds no string that
// secret scanners would flag.
func jwt(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("signature-not-checked"))
}

func TestParse(t *testing.T) {
	for _, c := range []struct {
		raw, want, kind, ns, err string
	}{
		{"https://abcdefghijklmnop.supabase.co", "https://abcdefghijklmnop.supabase.co/", string(Supabase), "", ""},
		{"https://abcdefghijklmnop.supabase.co/", "https://abcdefghijklmnop.supabase.co/", string(Supabase), "", ""},
		{"https://my-app-default-rtdb.firebaseio.com", "https://my-app-default-rtdb.firebaseio.com/", string(Firebase), "", ""},
		{"https://my-app.europe-west1.firebasedatabase.app/", "https://my-app.europe-west1.firebasedatabase.app/", string(Firebase), "", ""},
		{"http://127.0.0.1:54321", "http://127.0.0.1:54321/", "", "", ""},
		{"http://127.0.0.1:9000/?ns=demo-app", "http://127.0.0.1:9000/?ns=demo-app", string(Firebase), "demo-app", ""},
		{"http://abc.supabase.co", "", "", "", "use https"},
		{"https://abc.supabase.co/rest/v1", "", "", "", "no path"},
		{"https://abc.supabase.co/#x", "", "", "", "fragment"},
		{"https://abc.supabase.co/?select=*", "", "", "", "only one query parameter"},
		{"https://abc.supabase.co/?ns=x", "", "", "", "only to the Firebase emulator"},
		{"http://127.0.0.1:9000/?ns=a&ns=b", "", "", "", "only one query parameter"},
		{"http://127.0.0.1:9000/?ns=A_B", "", "", "", "only one query parameter"},
		{"ftp://x.supabase.co", "", "", "", "http"},
		{"https://user:pw@x.supabase.co", "", "", "", "user name"},
	} {
		b, err := Parse(c.raw)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.raw, err, c.err)
			}
			continue
		}
		if err != nil || b.String() != c.want || string(b.Kind) != c.kind || b.NS != c.ns {
			t.Errorf("%s: %+v %v", c.raw, b, err)
		}
	}
}

func TestReadScripts(t *testing.T) {
	b, _ := Parse("https://abcdefghijklmnop.supabase.co")
	anon := jwt(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"anon"}`)
	other := jwt(`{"iss":"supabase","ref":"someotherproject","role":"anon"}`)
	service := jwt(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"service_role"}`)
	files := map[string][]byte{
		"0.html": []byte(`<script src="/main.js"></script>`),
		"1.js": []byte(`const s=createClient("https://abcdefghijklmnop.supabase.co","` + service + `");const o="` + other + `";
const k="` + anon + `";
e.from("profiles").select("*");t.from('orders').select();n . from ( ` + "`notes`" + ` );
e.storage.from("avatars").upload();Array.from("abc");Buffer.from("xyz");e.from(name);e.from("bad/name")`),
		"2.js": []byte(`// no client here`),
	}
	s := ReadScripts(b, files)
	if !s.HostSeen || s.Kind != Supabase || s.Key != anon || s.KeyFile != "1.js" || !slices.Equal(s.Tables, []string{"notes", "orders", "profiles"}) {
		t.Errorf("%+v", s)
	}
	// A publishable key is used when there is no anon JWT for the project.
	s = ReadScripts(b, map[string][]byte{"1.js": []byte(`url="https://abcdefghijklmnop.supabase.co";k="sb_publishable_AbCdEf123456_x";` + other)})
	if s.Key != "sb_publishable_AbCdEf123456_x" {
		t.Errorf("publishable: %+v", s)
	}
	// Never a secret key.
	s = ReadScripts(b, map[string][]byte{"1.js": []byte(`k="sb_secret_AbCdEf123456";` + service)})
	if s.Key != "" || s.HostSeen {
		t.Errorf("secret: %+v", s)
	}
	// A local backend: the kind comes from the files that name it.
	lb, _ := Parse("http://127.0.0.1:54321")
	s = ReadScripts(lb, map[string][]byte{"1.js": []byte(`createClient("http://127.0.0.1:54321","` + jwt(`{"iss":"supabase-demo","role":"anon"}`) + `")`), "2.js": []byte("supabase")})
	if !s.HostSeen || s.Kind != Supabase || s.Key == "" {
		t.Errorf("local: %+v", s)
	}
	s = ReadScripts(lb, map[string][]byte{"1.js": []byte(`nothing`)})
	if s.HostSeen || s.Kind != "" {
		t.Errorf("unknown: %+v", s)
	}
	// Firebase paths.
	fb, _ := Parse("https://my-app-default-rtdb.firebaseio.com")
	s = ReadScripts(fb, map[string][]byte{"1.js": []byte(`databaseURL:"https://my-app-default-rtdb.firebaseio.com";ref(db,"users/"+uid);db.ref('messages');x.child("public/news/today");ref(db, ` + "`rooms/${id}`" + `);ref(db,"a.b");ref("$bad")`)})
	if !s.HostSeen || s.Kind != Firebase || !slices.Equal(s.Paths, []string{"messages", "public/news", "rooms", "users"}) {
		t.Errorf("firebase: %+v", s)
	}
}

func TestFirebasePath(t *testing.T) {
	for in, want := range map[string]string{
		"users": "users", "/users/": "users", "users/abc/x": "users/abc", "users/$uid": "users",
		"": "", "a.b": "", "#x": "", "rooms/${id}": "rooms", "users//x": "users",
	} {
		if got := FirebasePath(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestNames(t *testing.T) {
	n, over := Names([]string{"b", "a"}, []string{"a", "c"})
	if !slices.Equal(n, []string{"a", "b", "c"}) || over != 0 {
		t.Errorf("%v %d", n, over)
	}
	var many []string
	for i := range MaxNames + 5 {
		many = append(many, strings.Repeat("t", 1+i%3)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	n, over = Names(many)
	if len(n) != MaxNames || over != 5 {
		t.Errorf("%d %d", len(n), over)
	}
}

type fakeAnswer struct {
	status int
	body   string
	err    error
}

// useSend replaces send with answers by path and records the requests.
func useSend(t *testing.T, answers map[string]fakeAnswer) *[]string {
	t.Helper()
	var got []string
	oldSend, oldSleep := send, sleep
	send = func(_ context.Context, cfg egress.Config, method, path string, h http.Header, body []byte, max int64) (*egress.Answer, error) {
		if method != http.MethodGet || body != nil || !cfg.ReadOnly || max != MaxAnswer {
			t.Errorf("request %s %s read-only %v", method, path, cfg.ReadOnly)
		}
		got = append(got, path+" "+h.Get("Apikey")+" "+h.Get("Authorization"))
		a, ok := answers[path]
		if !ok {
			return &egress.Answer{Status: 404, Body: []byte(`{"code":"PGRST205"}`)}, nil
		}
		if a.status == 0 {
			return nil, a.err
		}
		return &egress.Answer{Status: a.status, Body: []byte(a.body)}, a.err
	}
	sleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { send, sleep = oldSend, oldSleep })
	return &got
}

func config(b *Backend) egress.Config {
	return egress.Config{Target: b.URL, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ReadOnly: true, Version: "test"}
}

func TestCheckSupabase(t *testing.T) {
	b, _ := Parse("https://abcdefghijklmnop.supabase.co")
	key := jwt(`{"role":"anon","ref":"abcdefghijklmnop"}`)
	got := useSend(t, map[string]fakeAnswer{
		"/rest/v1/profiles?select=*&limit=1": {200, `[{"id":1,"email":"a@b.test","full_name":"Ann"}]`, nil},
		"/rest/v1/orders?select=*&limit=1":   {200, `[]`, nil},
		"/rest/v1/secrets?select=*&limit=1":  {401, `{"code":"42501"}`, nil},
		"/rest/v1/weird?select=*&limit=1":    {500, `oops`, nil},
		"/rest/v1/big?select=*&limit=1":      {200, `[`, egress.ErrTooLarge},
	})
	r, err := Check(context.Background(), config(b), b, Supabase, key, []string{"big", "missing", "orders", "profiles", "secrets", "weird"}, 3)
	if err != nil || r.Tested != 6 || r.Requests != 6 || len(r.Readable) != 2 || r.Empty != 1 || r.Denied != 1 || r.Missing != 1 || r.Errors != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if !slices.Equal(r.Readable[1].Columns, []string{"email", "full_name", "id"}) || r.Readable[0].Name != "big" || r.Readable[0].Columns != nil {
		t.Errorf("readable %+v", r.Readable)
	}
	if (*got)[0] != "/rest/v1/big?select=*&limit=1 "+key+" Bearer "+key {
		t.Errorf("request %q", (*got)[0])
	}
	if s := r.Summary(); s != "6 tables tested: 2 readable, 1 empty or protected by row-level security, 1 refused (401 or 403), 1 not found (404), 1 other answers, 3 over the 200-name limit, not tested" {
		t.Errorf("summary %q", s)
	}
	fs := Findings(b, r, "002-main.js")
	if len(fs) != 2 || fs[1].RuleID != "supabase-table-readable" || fs[1].Location.URI != "https://abcdefghijklmnop.supabase.co/rest/v1/profiles" || fs[1].Severity != findings.High ||
		!slices.Equal(fs[1].CWEs, []string{"CWE-284", "CWE-862"}) || !strings.Contains(fs[1].Message, "Columns: email, full_name, id.") || fs[1].Fingerprint == "" {
		t.Errorf("findings %+v", fs)
	}
	// Values never reach a finding.
	for _, f := range fs {
		if strings.Contains(f.Message, "a@b.test") || strings.Contains(f.Message, "Ann") {
			t.Errorf("value in %q", f.Message)
		}
	}
	// A publishable key is not a JWT, so it goes only in apikey.
	got = useSend(t, map[string]fakeAnswer{"/rest/v1/t?select=*&limit=1": {200, `[]`, nil}})
	if _, err := Check(context.Background(), config(b), b, Supabase, "sb_publishable_x", []string{"t"}, 0); err != nil || (*got)[0] != "/rest/v1/t?select=*&limit=1 sb_publishable_x " {
		t.Errorf("publishable: %v %q", err, *got)
	}
}

func TestCheckFirebase(t *testing.T) {
	b, _ := Parse("http://127.0.0.1:9000/?ns=demo")
	got := useSend(t, map[string]fakeAnswer{
		"/.json?shallow=true&ns=demo":         {401, `{"error":"Permission denied"}`, nil},
		"/public.json?shallow=true&ns=demo":   {200, `{"a":true,"b":true}`, nil},
		"/users.json?shallow=true&ns=demo":    {401, `{"error":"Permission denied"}`, nil},
		"/empty.json?shallow=true&ns=demo":    {200, `null`, nil},
		"/count.json?shallow=true&ns=demo":    {200, `5`, nil},
		"/a%20b/c.json?shallow=true&ns=demo":  {200, `{"x":true}`, nil},
		"/missing.json?shallow=true&ns=demo":  {404, ``, nil},
		"/offline.json?shallow=true&ns=demo":  {0, ``, errors.New("refused")},
		"/public2.json?shallow=true&ns=demo":  {403, ``, nil},
		"/notjson.json?shallow=true&ns=demo":  {200, `<html>`, nil},
		"/weird.json?shallow=true&ns=demo":    {302, ``, nil},
		"/ignored.json?shallow=true&ns=demo":  {200, `{}`, nil},
		"/ignored2.json?shallow=true&ns=demo": {200, `[]`, nil},
	})
	r, err := Check(context.Background(), config(b), b, Firebase, "", []string{"public", "users", "empty", "count", "a b/c", "missing", "offline", "notjson", "weird"}, 0)
	if err != nil || r.Tested != 10 || r.RootOpen || len(r.Readable) != 3 || r.Denied != 2 || r.Empty != 1 || r.Missing != 1 || r.Errors != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	if (*got)[0] != "/.json?shallow=true&ns=demo  " {
		t.Errorf("root first, no key: %q", (*got)[0])
	}
	fs := Findings(b, r, "002-main.js")
	if len(fs) != 3 || fs[0].RuleID != "firebase-rtdb-readable" || fs[0].Location.URI != "http://127.0.0.1:9000/public.json" || !strings.Contains(fs[0].Message, "2 key(s) at /public") {
		t.Errorf("findings %+v", fs)
	}
	// An open root stops the check: everything under it is readable.
	got = useSend(t, map[string]fakeAnswer{"/.json?shallow=true&ns=demo": {200, `{"users":true}`, nil}})
	r, err = Check(context.Background(), config(b), b, Firebase, "", []string{"users", "x"}, 0)
	if err != nil || !r.RootOpen || len(*got) != 1 || r.Summary() != "the database root is readable without signing in" || Findings(b, r, "")[0].Location.URI != "http://127.0.0.1:9000/.json" {
		t.Errorf("root: %+v %v %v", r, err, *got)
	}
}

func TestCheckFails(t *testing.T) {
	b, _ := Parse("https://abcdefghijklmnop.supabase.co")
	useSend(t, map[string]fakeAnswer{"/rest/v1/a?select=*&limit=1": {0, "", errors.New("connection refused")}})
	cfg := config(b)
	for _, c := range []struct {
		kind  Kind
		key   string
		names []string
		cfg   egress.Config
		want  string
	}{
		{Supabase, "k", []string{"a"}, cfg, "did not answer"},
		{Supabase, "", []string{"a"}, cfg, "no Supabase public key"},
		{Supabase, "k", nil, cfg, "no table names"},
		{"", "k", []string{"a"}, cfg, "cannot tell"},
		{Supabase, "k", []string{"a"}, egress.Config{Target: b.URL}, "read-only"},
	} {
		if _, err := Check(context.Background(), c.cfg, b, c.kind, c.key, c.names, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	useSend(t, map[string]fakeAnswer{"/rest/v1/a?select=*&limit=1": {400, "", nil}, "/rest/v1/b?select=*&limit=1": {500, "", nil}})
	if _, err := Check(context.Background(), cfg, b, Supabase, "k", []string{"a", "b"}, 0); err == nil || !strings.Contains(err.Error(), "no answer this check can read") {
		t.Errorf("all errors: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	if _, err := Check(ctx, cfg, b, Supabase, "k", []string{"a", "b"}, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestRequestPath(t *testing.T) {
	for _, c := range []struct {
		kind     Kind
		name, ns string
		want     string
	}{
		{Supabase, "profiles", "", "/rest/v1/profiles?select=*&limit=1"},
		{Supabase, "My Table", "", "/rest/v1/My%20Table?select=*&limit=1"},
		{Supabase, "../x", "", "/rest/v1/..%2Fx?select=*&limit=1"},
		{Firebase, "", "", "/.json?shallow=true"},
		{Firebase, "users/x", "a", "/users/x.json?shallow=true&ns=a"},
	} {
		if got := RequestPath(c.kind, c.name, c.ns); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

// FuzzReadScripts checks that reading any file never panics and never
// returns a key that is not an anon JWT or a publishable key, or a table
// name a request path cannot carry.
func FuzzReadScripts(f *testing.F) {
	f.Add(`createClient("https://abcdefghijklmnop.supabase.co","` + jwt(`{"role":"anon"}`) + `");e.from("t")`)
	f.Add(`ref(db,"users/"+x);db.ref('a/b/c').child("d")`)
	f.Add("sb_publishable_xxxxxxxxxx sb_secret_yyyyyyyyyy")
	b, _ := Parse("https://abcdefghijklmnop.supabase.co")
	f.Fuzz(func(t *testing.T, data string) {
		s := ReadScripts(b, map[string][]byte{"1.js": []byte(data)})
		if s.Key != "" && !strings.HasPrefix(s.Key, "sb_publishable_") && !anonKey(s.Key, "abcdefghijklmnop") {
			t.Errorf("key %q", s.Key)
		}
		for _, n := range s.Tables {
			if p := RequestPath(Supabase, n, ""); !strings.HasPrefix(p, "/rest/v1/") || strings.Count(p, "/") != 3 || strings.ContainsAny(n, "\"'`\\") {
				t.Errorf("table %q -> %q", n, p)
			}
		}
		for _, p := range s.Paths {
			if p == "" || strings.Count(p, "/") > 1 || strings.ContainsAny(p, ".$#[]") {
				t.Errorf("path %q", p)
			}
		}
	})
}

// FuzzParse checks that an accepted --backend-url has no path, no user
// name and at most the ns query.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"https://abc.supabase.co", "http://127.0.0.1:9000/?ns=demo", "https://x.firebaseio.com/a", "https://a.supabase.co/?ns=x", "http://[::1]:54321/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		b, err := Parse(raw)
		if err != nil {
			return
		}
		if b.URL.Path != "/" || strings.Contains(b.String(), "@") || strings.Contains(b.String(), "#") {
			t.Errorf("%q -> %q", raw, b.String())
		}
		if b.NS != "" && !reNS.MatchString(b.NS) {
			t.Errorf("ns %q", b.NS)
		}
		if (b.Kind == Supabase || strings.HasSuffix(b.URL.Host, ".firebaseio.com")) && b.URL.Scheme != "https" {
			t.Errorf("hosted over http: %q", raw)
		}
	})
}

// TestCheckOverHTTP sends real requests through egress to servers that
// answer as PostgREST v16.6 and the Realtime Database emulator 4.11.2 did
// when measured on 2026-11-20 (RLS off: a row; RLS on with no policy: [];
// unknown table: 404 PGRST205; closed path: 401 Permission denied).
func TestCheckOverHTTP(t *testing.T) {
	key := jwt(`{"role":"anon","iss":"supabase"}`)
	var got []string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Apikey") != key || r.Header.Get("Authorization") != "Bearer "+key || !strings.HasPrefix(r.UserAgent(), "SiegeKit/") {
			t.Errorf("headers %v", r.Header)
		}
		switch r.URL.Path {
		case "/rest/v1/profiles":
			_, _ = w.Write([]byte(`[{"id":1,"email":"alice@example.test"}]`))
		case "/rest/v1/private_notes":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"PGRST205"}`))
		}
	}))
	defer rest.Close()
	b, err := Parse(rest.URL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), config(b), b, Supabase, key, []string{"nope", "private_notes", "profiles"}, 0)
	if err != nil || r.Tested != 3 || r.Requests != 3 || r.Empty != 1 || r.Missing != 1 || len(r.Readable) != 1 ||
		!slices.Equal(r.Readable[0].Columns, []string{"email", "id"}) {
		t.Fatalf("supabase %+v %v", r, err)
	}
	if want := []string{"GET /rest/v1/nope?select=*&limit=1", "GET /rest/v1/private_notes?select=*&limit=1", "GET /rest/v1/profiles?select=*&limit=1"}; !slices.Equal(got, want) {
		t.Errorf("requests %q", got)
	}

	got = nil
	rtdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "" || r.Header.Get("Apikey") != "" {
			t.Errorf("Firebase request with a key: %v", r.Header)
		}
		if r.URL.Path == "/public.json" {
			_, _ = w.Write([]byte(`{"room-alpha":true,"room-beta":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
	}))
	defer rtdb.Close()
	b, err = Parse(rtdb.URL + "?ns=demo")
	if err != nil {
		t.Fatal(err)
	}
	r, err = Check(context.Background(), config(b), b, Firebase, "", []string{"public", "users"}, 0)
	if err != nil || r.Tested != 3 || r.Denied != 2 || len(r.Readable) != 1 || r.Readable[0].Children != 2 || r.RootOpen {
		t.Fatalf("firebase %+v %v", r, err)
	}
	if want := []string{"GET /.json?shallow=true&ns=demo", "GET /public.json?shallow=true&ns=demo", "GET /users.json?shallow=true&ns=demo"}; !slices.Equal(got, want) {
		t.Errorf("requests %q", got)
	}
	for _, f := range Findings(b, r, "") {
		if strings.Contains(f.Message, "room-") || f.Location.URI != rtdb.URL+"/public.json" {
			t.Errorf("finding %+v", f)
		}
	}
}
