package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestParseStorage(t *testing.T) {
	for _, c := range []struct {
		raw, kind, err string
		hosted         bool
	}{
		{"https://abcdefghijklmnop.supabase.co", string(SupabaseStorage), "", false},
		{"https://firebasestorage.googleapis.com/", string(FirebaseStorage), "", true},
		{"http://127.0.0.1:9199", "", "", false},
		{"http://127.0.0.1:54321/", "", "", false},
		{"http://abc.supabase.co", "", "use https", false},
		{"http://firebasestorage.googleapis.com", "", "use https", false},
		{"https://abc.supabase.co/storage/v1", "", "no path", false},
		{"https://firebasestorage.googleapis.com/v0/b/x.appspot.com", "", "no path", false},
		{"https://abc.supabase.co/?x=1", "", "query", false},
		{"https://abc.supabase.co/?", "", "query", false},
		{"https://abc.supabase.co/#x", "", "fragment", false},
		{"ftp://abc.supabase.co", "", "http", false},
		{"https://user:pw@abc.supabase.co", "", "user name", false},
	} {
		s, err := ParseStorage(c.raw)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.raw, err, c.err)
			}
			continue
		}
		if err != nil || string(s.Kind) != c.kind || s.Hosted() != c.hosted {
			t.Errorf("%s: %+v %v", c.raw, s, err)
		}
	}
}

func TestFolder(t *testing.T) {
	for in, want := range map[string]string{
		"uploads/":                "uploads/",
		"uploads/x.png":           "uploads/",
		"/uploads/":               "uploads/",
		"users/avatars/":          "users/avatars/",
		"a/b/c/d/e/":              "a/b/c/",
		"x.png":                   "",
		"":                        "",
		"/":                       "",
		"../etc/":                 "",
		"a b/":                    "",
		"public/":                 "public/",
		"https://example.test/a/": "",
	} {
		if got := Folder(in); got != want {
			t.Errorf("Folder(%q) = %q, want %q", in, got, want)
		}
	}
}

// The scripts are cut from real esbuild 0.25.0 bundles of the firebase 12
// and supabase-js 2.49.4 web SDKs (minified: firebase's ref() is renamed
// to Ue) and from the Firebase app unminified, as a dev server serves it.
const (
	firebaseMinified = `gt="firebasestorage.googleapis.com",bt="storageBucket";` +
		`initializeApp({apiKey:"AIzaSy-not-a-key",authDomain:"demo-siegekit.firebaseapp.com",projectId:"demo-siegekit",storageBucket:"demo-siegekit.appspot.com",appId:"1:123:web:abc"}),Be=Nt(Q);` +
		"async function es(e,t){let n=Ue(Be,`uploads/${t}/${e.name}`);await Ne(n,e);let r=Ue(Be,\"avatars/\"+t+\".png\")}"
	firebaseDev = `const storage = getStorage(app, "gs://demo-second-bucket");` +
		"const r = ref(storage, `uploads/${uid}/${file.name}`); const a = ref(storage, \"avatars/\" + uid + \".png\"); storageRef.child('docs/readme.txt'); ref(storage, 'top.txt')"
	supabaseMinified = "var Is={\"X-Client-Info\":`supabase-js-${Ae}/${ur}`};" + `const It=createClient("http://127.0.0.1:54321","%s");` +
		"async function si(s,e){await It.storage.from(\"files\").upload(`uploads/${e}/${s.name}`,s),await It.storage.from(\"avatars\");" +
		"const b=It.storage.from(\"avatars\");await b.upload(\"public/\"+e+\".png\",s,{upsert:!0});const{data:d}=await It.from(\"profiles\").select(\"*\")}" +
		`Array.from("x");` + "`${this.url}/${a}/public/${r}`"
)

func TestReadStorageScripts(t *testing.T) {
	fb, _ := ParseStorage("http://127.0.0.1:9199")
	sc := ReadStorageScripts(fb, map[string][]byte{"main.js": []byte(firebaseMinified)})
	if sc.Kind != FirebaseStorage || !slices.Equal(sc.Buckets, []string{"demo-siegekit.appspot.com"}) || len(sc.Folders) != 0 || sc.Key != "" {
		t.Errorf("firebase minified %+v", sc)
	}
	sc = ReadStorageScripts(fb, map[string][]byte{"main.js": []byte(firebaseMinified), "dev.js": []byte(firebaseDev)})
	if !slices.Equal(sc.Buckets, []string{"demo-second-bucket", "demo-siegekit.appspot.com"}) || !slices.Equal(sc.Folders, []string{"avatars/", "docs/", "uploads/"}) {
		t.Errorf("firebase dev %+v", sc)
	}
	hosted, _ := ParseStorage("https://firebasestorage.googleapis.com")
	if sc := ReadStorageScripts(hosted, map[string][]byte{"main.js": []byte(firebaseMinified)}); sc.Kind != FirebaseStorage || !sc.HostSeen || len(sc.Buckets) != 1 {
		t.Errorf("firebase hosted %+v", sc)
	}

	anon := jwt(`{"role":"anon","iss":"supabase-demo"}`)
	service := jwt(`{"role":"service_role","iss":"supabase-demo"}`)
	sb, _ := ParseStorage("http://127.0.0.1:54321")
	sc = ReadStorageScripts(sb, map[string][]byte{"main.js": []byte(fmt.Sprintf(supabaseMinified, anon))})
	if sc.Kind != SupabaseStorage || !sc.HostSeen || sc.Key != anon || sc.KeyFile != "main.js" ||
		!slices.Equal(sc.Buckets, []string{"avatars", "files"}) || !slices.Equal(sc.Folders, []string{"public/", "uploads/"}) ||
		!slices.Equal(sc.Pairs, []Location{{Bucket: "files", Folder: "uploads/"}}) {
		t.Errorf("supabase %+v", sc)
	}
	// A service key is never used, and a file that names no backend gives
	// no kind.
	if sc := ReadStorageScripts(sb, map[string][]byte{"main.js": []byte(fmt.Sprintf(supabaseMinified, service))}); sc.Key != "" {
		t.Errorf("service key used: %+v", sc)
	}
	if sc := ReadStorageScripts(sb, map[string][]byte{"main.js": []byte(`console.log("hi")`)}); sc.Kind != "" || sc.HostSeen {
		t.Errorf("no backend %+v", sc)
	}
}

func TestPlanFiles(t *testing.T) {
	n := 0
	old := randomName
	randomName = func() (string, error) { n++; return fmt.Sprintf("siegekit-write-test-%d.txt", n), nil }
	t.Cleanup(func() { randomName = old })
	locs, left, err := PlanFiles([]string{"a", "b"}, []Location{{Bucket: "b", Folder: "x/"}, {Bucket: "c", Folder: "y/"}}, []string{"uploads/", "public/", "x/"})
	if err != nil || left != 4 || len(locs) != MaxFiles {
		t.Fatalf("%v %d %v", locs, left, err)
	}
	var where []string
	for _, l := range locs {
		where = append(where, l.Where(SupabaseStorage))
	}
	// Roots, then the pairs the scripts name (a bucket the scripts only
	// name in a pair still gets that folder), then the other folders.
	want := []string{"a/siegekit-write-test-1.txt", "b/siegekit-write-test-2.txt", "b/x/siegekit-write-test-3.txt", "c/y/siegekit-write-test-4.txt", "a/uploads/siegekit-write-test-5.txt"}
	if !slices.Equal(where, want) {
		t.Errorf("%q", where)
	}
	if got := locs[4].Where(FirebaseStorage); got != "gs://a/uploads/siegekit-write-test-5.txt" {
		t.Errorf("%s", got)
	}
	randomName = old
	locs, _, _ = PlanFiles([]string{"a"}, nil, nil)
	if len(locs) != 1 || !strings.HasPrefix(locs[0].Name, "siegekit-write-test-") || len(locs[0].Name) != len("siegekit-write-test-")+16+len(".txt") {
		t.Errorf("%+v", locs)
	}
	if len(TestContent) != 36 {
		t.Errorf("test file is %d bytes", len(TestContent))
	}
}

// fakeStorage answers as the Firebase Storage emulator (firebase-tools
// 15.37.0) and Supabase storage-api v1.94.2 did when measured on
// 2026-11-23: see the ADR 0058 evidence. rules says what a request with
// no login (or the anon key) may do at a path.
type fakeStorage struct {
	mu      sync.Mutex
	kind    StorageKind
	objects map[string]string // "bucket/path" -> content
	rules   func(op, path string) bool
	got     []string
}

func (f *fakeStorage) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func (f *fakeStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, r.Method+" "+r.URL.EscapedPath())
	body, _ := io.ReadAll(r.Body)
	if f.kind == FirebaseStorage {
		f.firebase(w, r, body)
		return
	}
	f.supabase(w, r, body)
}

func (f *fakeStorage) firebase(w http.ResponseWriter, r *http.Request, body []byte) {
	denied := func() {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Permission denied. No WRITE permission."}}`))
	}
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/v0/b/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	bucket, obj, _ := strings.Cut(rest, "/o")
	obj = strings.TrimPrefix(obj, "/")
	name, _ := url.PathUnescape(obj)
	key := bucket + "/" + name
	switch {
	case r.Method == http.MethodPost && obj == "":
		name = r.URL.Query().Get("name")
		if r.Header.Get("X-Goog-Upload-Protocol") != "multipart" || !strings.Contains(string(body), "\r\n\r\n"+TestContent+"\r\n") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !f.rules("write", name) {
			denied()
			return
		}
		f.objects[bucket+"/"+name] = TestContent
		_, _ = w.Write([]byte(`{"name":"` + name + `","bucket":"` + bucket + `","size":"36"}`))
	case r.Method == http.MethodGet:
		if !f.rules("read", name) {
			denied()
			return
		}
		c, ok := f.objects[key]
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
		case r.URL.Query().Get("alt") == "media":
			_, _ = w.Write([]byte(c))
		default:
			_, _ = w.Write([]byte(`{"name":"` + name + `"}`))
		}
	case r.Method == http.MethodDelete:
		if !f.rules("delete", name) {
			denied()
			return
		}
		if _, ok := f.objects[key]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeStorage) supabase(w http.ResponseWriter, r *http.Request, body []byte) {
	fail := func(code, msg string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"statusCode":"` + code + `","error":"x","message":"` + msg + `"}`))
	}
	if r.Header.Get("Apikey") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail("403", "no key")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/storage/v1/object/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rest, _ = url.PathUnescape(rest)
	bucket, name, _ := strings.Cut(rest, "/")
	if bucket != "files" {
		fail("404", "Bucket not found")
		return
	}
	key := bucket + "/" + name
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("X-Upsert") != "false" || string(body) != TestContent {
			fail("400", "bad")
			return
		}
		if !f.rules("insert", name) {
			fail("403", "new row violates row-level security policy")
			return
		}
		f.objects[key] = TestContent
		_, _ = w.Write([]byte(`{"Key":"` + key + `","Id":"x"}`))
	case http.MethodGet:
		c, ok := f.objects[key]
		if !ok || !f.rules("select", name) {
			fail("404", "Object not found")
			return
		}
		_, _ = w.Write([]byte(c))
	case http.MethodDelete:
		var req struct {
			Prefixes []string `json:"prefixes"`
		}
		if name != "" || json.Unmarshal(body, &req) != nil {
			fail("400", "bad")
			return
		}
		var deleted []map[string]string
		for _, p := range req.Prefixes {
			// storage-api finds the rows first, so a delete also needs select.
			if _, ok := f.objects[bucket+"/"+p]; ok && f.rules("select", p) && f.rules("delete", p) {
				delete(f.objects, bucket+"/"+p)
				deleted = append(deleted, map[string]string{"name": p, "bucket_id": bucket})
			}
		}
		if deleted == nil {
			deleted = []map[string]string{}
		}
		b, _ := json.Marshal(deleted)
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func storageConfig(s *Storage) egress.Config {
	return egress.Config{Target: s.URL, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
}

func noSleep(t *testing.T) {
	t.Helper()
	old := sleep
	sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { sleep = old })
}

func allow(ops ...string) func(op, path string) bool {
	return func(op, _ string) bool { return slices.Contains(ops, op) }
}

// TestWriteStorageFirebase repeats the emulator measurement over real
// HTTP: v1 open, v3 a size-only write rule (the delete is refused), v4
// login only, v5 open under uploads/ only, v6 create without delete, and
// v7 write without read.
func TestWriteStorageFirebase(t *testing.T) {
	noSleep(t)
	under := func(op, p string) bool { return strings.HasPrefix(p, "uploads/") }
	for _, c := range []struct {
		name                         string
		rules                        func(op, path string) bool
		written, readable, leftovers int
	}{
		{"v1", allow("read", "write", "delete"), 2, 2, 0},
		{"v3", allow("read", "write"), 2, 2, 2},
		{"v4", allow(), 0, 0, 0},
		{"v5", under, 1, 1, 0},
		{"v6", allow("read", "write"), 2, 2, 2},
		{"v7", allow("write", "delete"), 2, 0, 0},
	} {
		f := &fakeStorage{kind: FirebaseStorage, objects: map[string]string{"demo.appspot.com/keep.png": "x"}, rules: c.rules}
		srv := httptest.NewServer(f)
		s, _ := ParseStorage(srv.URL)
		locs, _, _ := PlanFiles([]string{"demo.appspot.com"}, nil, []string{"uploads/"})
		before := f.count()
		r, err := WriteStorage(context.Background(), storageConfig(s), FirebaseStorage, "", locs, 0)
		srv.Close()
		if err != nil || len(r.Outcomes) != 2 || len(r.Written()) != c.written || len(r.Leftovers()) != c.leftovers {
			t.Errorf("%s: %+v %v", c.name, r, err)
			continue
		}
		readable := 0
		for _, o := range r.Outcomes {
			if o.Readable {
				readable++
			}
			if o.Written && !o.Left && f.objects["demo.appspot.com/"+o.Path()] != "" {
				t.Errorf("%s: %s reported deleted but still there", c.name, o.Path())
			}
		}
		if readable != c.readable || f.count()-before != c.leftovers {
			t.Errorf("%s: readable %d, objects %d -> %d", c.name, readable, before, f.count())
		}
		// 4 requests per written file, 1 per refused upload.
		if want := c.written*4 + (2 - c.written); r.Requests != want || len(f.got) != want {
			t.Errorf("%s: %d requests (%d seen), want %d: %q", c.name, r.Requests, len(f.got), want, f.got)
		}
		if c.name == "v1" {
			p := url.PathEscape(locs[1].Path())
			want := []string{"POST /v0/b/demo.appspot.com/o", "GET /v0/b/demo.appspot.com/o/" + strings.ReplaceAll(p, "/", "%2F"), "DELETE /v0/b/demo.appspot.com/o/" + strings.ReplaceAll(p, "/", "%2F")}
			if !slices.Contains(f.got, want[0]) || !slices.Contains(f.got, want[1]) || !slices.Contains(f.got, want[2]) {
				t.Errorf("v1 requests %q, want %q", f.got, want)
			}
		}
		if c.leftovers > 0 && !strings.Contains(r.Summary(), "may still be there, delete them: gs://demo.appspot.com/"+locs[0].Name) {
			t.Errorf("%s: summary %s", c.name, r.Summary())
		}
	}
}

// TestWriteStorageSupabase repeats the local storage-api measurement over
// real HTTP: s1 all to anon, s3 insert and delete but no select (the
// delete finds no row), s4 authenticated only, s5 anon under uploads/
// only, s6 insert and select with no delete policy, plus a bucket that
// does not exist.
func TestWriteStorageSupabase(t *testing.T) {
	noSleep(t)
	key := jwt(`{"role":"anon"}`)
	under := func(op, p string) bool { return strings.HasPrefix(p, "uploads/") }
	for _, c := range []struct {
		name                         string
		rules                        func(op, path string) bool
		written, readable, leftovers int
	}{
		{"s1", allow("insert", "select", "delete"), 2, 2, 0},
		{"s3", allow("insert", "delete"), 2, 0, 2},
		{"s4", allow(), 0, 0, 0},
		{"s5", under, 1, 1, 0},
		{"s6", allow("insert", "select"), 2, 2, 2},
	} {
		f := &fakeStorage{kind: SupabaseStorage, objects: map[string]string{"files/keep.png": "x"}, rules: c.rules}
		srv := httptest.NewServer(f)
		s, _ := ParseStorage(srv.URL)
		locs, _, _ := PlanFiles([]string{"files", "missing"}, nil, []string{"uploads/"})
		before := f.count()
		r, err := WriteStorage(context.Background(), storageConfig(s), SupabaseStorage, key, locs, 0)
		srv.Close()
		if err != nil || len(r.Outcomes) != 4 || len(r.Written()) != c.written || len(r.Leftovers()) != c.leftovers || f.count()-before != c.leftovers {
			t.Errorf("%s: %+v %v, objects %d -> %d", c.name, r, err, before, f.count())
			continue
		}
		readable, missing := 0, 0
		for _, o := range r.Outcomes {
			if o.Readable {
				readable++
			}
			if o.Missing {
				missing++
			}
		}
		if readable != c.readable || missing != 2 {
			t.Errorf("%s: readable %d, missing %d", c.name, readable, missing)
		}
		if c.name == "s1" {
			want := "DELETE /storage/v1/object/files"
			if !slices.Contains(f.got, want) || !slices.Contains(f.got, "POST /storage/v1/object/files/uploads/"+locs[2].Name) {
				t.Errorf("s1 requests %q", f.got)
			}
		}
	}
}

// An interrupt after an accepted upload still deletes the file.
func TestWriteStorageInterrupted(t *testing.T) {
	f := &fakeStorage{kind: FirebaseStorage, objects: map[string]string{}, rules: allow("read", "write", "delete")}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, _ := ParseStorage(srv.URL)
	locs, _, _ := PlanFiles([]string{"demo.appspot.com"}, nil, []string{"uploads/"})
	ctx, cancel := context.WithCancel(context.Background())
	old := sleep
	calls := 0
	sleep = func(c context.Context, _ time.Duration) error {
		if calls++; calls == 1 {
			cancel() // after the first upload, before its read
		}
		return c.Err()
	}
	t.Cleanup(func() { sleep = old })
	r, err := WriteStorage(ctx, storageConfig(s), FirebaseStorage, "", locs, 0)
	if err == nil || len(r.Outcomes) != 1 || !r.Outcomes[0].Written || r.Outcomes[0].Left || f.count() != 0 {
		t.Fatalf("%+v %v, %d objects, %q", r, err, f.count(), f.got)
	}
	if !slices.Contains(f.got, "DELETE /v0/b/demo.appspot.com/o/"+locs[0].Name) {
		t.Errorf("no delete: %q", f.got)
	}
}

func TestWriteStorageFails(t *testing.T) {
	noSleep(t)
	s, _ := ParseStorage("http://127.0.0.1:9199")
	locs := []Location{{Bucket: "b", Name: "siegekit-write-test-0.txt"}}
	ro := storageConfig(s)
	ro.ReadOnly = true
	for _, c := range []struct {
		cfg  egress.Config
		kind StorageKind
		key  string
		locs []Location
		want string
	}{
		{ro, FirebaseStorage, "", locs, "allows POST and DELETE"},
		{storageConfig(s), SupabaseStorage, "", locs, "no Supabase public key"},
		{storageConfig(s), "", "", locs, "cannot tell"},
		{storageConfig(s), FirebaseStorage, "", nil, "no bucket name"},
	} {
		if _, err := WriteStorage(context.Background(), c.cfg, c.kind, c.key, c.locs, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.want, err)
		}
	}
	// A server that answers 500 to everything: no readable answer, an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	s, _ = ParseStorage(srv.URL)
	r, err := WriteStorage(context.Background(), storageConfig(s), FirebaseStorage, "", locs, 0)
	if err == nil || !strings.Contains(err.Error(), "no answer this check can read") || r.Requests != 1 {
		t.Errorf("%+v %v", r, err)
	}
}

func TestStorageFindings(t *testing.T) {
	s, _ := ParseStorage("https://abcdefghijklmnop.supabase.co")
	r := StorageResult{Kind: SupabaseStorage, Outcomes: []Outcome{
		{Location: Location{Bucket: "files", Name: "siegekit-write-test-1.txt"}, Written: true, Readable: true, Deleted: true},
		{Location: Location{Bucket: "files", Folder: "uploads/", Name: "siegekit-write-test-2.txt"}, Written: true, Left: true},
		{Location: Location{Bucket: "files", Folder: "x/", Name: "siegekit-write-test-3.txt"}, Refused: true},
	}}
	fs := StorageFindings(s, r, "002-main.js")
	if len(fs) != 2 {
		t.Fatalf("%+v", fs)
	}
	if fs[0].Severity != findings.Critical || fs[0].RuleID != "storage-public-write" || fs[0].Location.URI != "https://abcdefghijklmnop.supabase.co/storage/v1/object/files/" ||
		!strings.Contains(fs[0].Message, "read back") || strings.Contains(fs[0].Message, "could not confirm") {
		t.Errorf("%+v", fs[0])
	}
	if fs[1].Location.URI != "https://abcdefghijklmnop.supabase.co/storage/v1/object/files/uploads/" || !strings.Contains(fs[1].Message, "delete files/uploads/siegekit-write-test-2.txt yourself") {
		t.Errorf("%+v", fs[1])
	}
	// The same bucket and folder give the same fingerprint whatever the
	// random file name.
	r.Outcomes[0].Name = "siegekit-write-test-9.txt"
	if again := StorageFindings(s, r, "002-main.js"); again[0].Fingerprint != fs[0].Fingerprint {
		t.Error("fingerprint depends on the file name")
	}
	fb, _ := ParseStorage("https://firebasestorage.googleapis.com")
	fr := StorageFindings(fb, StorageResult{Kind: FirebaseStorage, Outcomes: []Outcome{{Location: Location{Bucket: "demo.appspot.com", Folder: "uploads/", Name: "n.txt"}, Written: true}}}, "")
	if len(fr) != 1 || fr[0].Location.URI != "gs://demo.appspot.com/uploads/" || !strings.Contains(fr[0].Message, "with no login") {
		t.Errorf("%+v", fr)
	}
	if got := r.Summary(); got != "3 location(s) tested: 2 accepted an upload with no login, 1 read back, 1 refused; 1 test file(s) may still be there, delete them: files/uploads/siegekit-write-test-2.txt" {
		t.Errorf("summary %s", got)
	}
}

// FuzzReadStorageScripts checks that whatever the scripts say, every
// request stays inside a named bucket: no dot segments, nothing that
// changes the path or query, at most MaxFiles files.
func FuzzReadStorageScripts(f *testing.F) {
	f.Add(firebaseMinified)
	f.Add(firebaseDev)
	f.Add(fmt.Sprintf(supabaseMinified, jwt(`{"role":"anon"}`)))
	f.Add(`supabase.storage.from("..").upload("../../x/y",f);x.storage.from("a?b").upload("c#/d/",f)`)
	f.Add(`firebase storageBucket:"a..b" ref(s,"./x/") ref(s,"%2e%2e/x/")`)
	fb, _ := ParseStorage("http://127.0.0.1:9199")
	sb, _ := ParseStorage("http://127.0.0.1:54321")
	f.Fuzz(func(t *testing.T, data string) {
		for _, s := range []*Storage{fb, sb} {
			sc := ReadStorageScripts(s, map[string][]byte{"1.js": []byte(data)})
			for _, kind := range []StorageKind{FirebaseStorage, SupabaseStorage} {
				locs, _, err := PlanFiles(sc.Buckets, sc.Pairs, sc.Folders)
				if err != nil || len(locs) > MaxFiles {
					t.Fatalf("%v %v", locs, err)
				}
				for _, l := range locs {
					_, up, _, _ := uploadRequest(kind, l)
					dm, del, _, _ := deleteRequest(kind, l)
					for _, p := range []string{up, readPath(kind, l), checkPath(kind, l), del} {
						path, _, _ := strings.Cut(p, "?")
						if !target.SendablePath(p) || strings.Contains(path, "/../") || strings.Contains(path, "/./") || strings.HasSuffix(path, "/..") || strings.ContainsAny(path, "#") {
							t.Errorf("%s %+v -> %q", kind, l, p)
						}
					}
					if dm != http.MethodDelete || strings.Contains(l.Bucket, "/") || strings.Contains(l.Name, "/") {
						t.Errorf("%+v", l)
					}
				}
			}
		}
	})
}

// FuzzParseStorage checks that an accepted --storage-url has no path,
// query or user name.
func FuzzParseStorage(f *testing.F) {
	for _, s := range []string{"https://abc.supabase.co", "https://firebasestorage.googleapis.com/", "http://127.0.0.1:9199", "http://x/?a", "https://u@x.supabase.co"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := ParseStorage(raw)
		if err != nil {
			return
		}
		if s.URL.Path != "/" || strings.ContainsAny(raw, "?#") || s.URL.Host == "" || (s.Kind != "" && s.URL.Scheme != "https") {
			t.Errorf("%q accepted as %+v", raw, s.URL)
		}
	})
}
