package served

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestLinks(t *testing.T) {
	page := `<!doctype html><html><head>
<!-- <script src="/commented.js"></script> -->
<link rel="stylesheet" href="/a.css"><LINK REL=modulepreload HREF=/m.js>
<link rel="icon" href="/favicon.ico"><link rel="manifest" href='/manifest.json'>
<link rel="preload" as="script" href="/p.js"><link rel="preload" as="image" href="/i.png">
<link rel="prefetch" as="fetch" href="/data.json"><link rel="preload stylesheet" as="style" href="/s.css">
<script>var s = '<script src="/in-string.js"></script>';</script>
<style>a{background:url("/x.png")} </style><script src="/in-style.js"></script>
<script type="module" src="/app.js?v=1&amp;x=2"></script>
<script src=""></script><script src = "  /spaced.js  " defer></script>
</head><body><img src="/img.png"></body></html>`
	got := Links([]byte(page))
	want := []Link{
		{Style, "/a.css"}, {Script, "/m.js"}, {JSON, "/manifest.json"}, {Script, "/p.js"},
		{JSON, "/data.json"}, {Style, "/s.css"}, {Script, "/in-style.js"}, {Script, "/app.js?v=1&x=2"}, {Script, "/spaced.js"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Links =\n%v\nwant\n%v", got, want)
	}
	// Broken markup never panics and still finds what it can.
	for _, p := range []string{"<", "<script", "<script src=", `<script src="/x.js`, "<link rel=stylesheet href=/a.css", "<!--", "<script src=/a.js>"} {
		Links([]byte(p))
	}
	if got := Links([]byte("<script src=/a.js>")); !slices.Equal(got, []Link{{Script, "/a.js"}}) {
		t.Errorf("unclosed script: %v", got)
	}
}

func TestSourceMapRef(t *testing.T) {
	for in, want := range map[string]string{
		"a();\n//# sourceMappingURL=app.js.map\n":                "app.js.map",
		"a();\n//@ sourceMappingURL=old.map":                     "old.map",
		"a{}\n/*# sourceMappingURL=s.css.map */":                 "s.css.map",
		"x = 'sourceMappingURL=no.map'":                          "",
		"//# sourceMappingURL=":                                  "",
		"//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map": "b.map",
		"sourceMappingURL=a.map":                                 "",
	} {
		if got := SourceMapRef([]byte(in)); got != want {
			t.Errorf("SourceMapRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzLinks(f *testing.F) {
	f.Add([]byte(`<script src="/a.js"></script><link rel=stylesheet href=/b.css>`))
	f.Add([]byte(`<!-- x --><script>"</script"</script><link rel="preload" as="fetch" href='/c.json'>`))
	f.Add([]byte("//# sourceMappingURL=a.map"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, l := range Links(b) {
			if l.Ref == "" || len(l.Ref) > maxRef || !slices.Contains([]Kind{Script, Style, JSON}, l.Kind) {
				t.Fatalf("bad link %+v", l)
			}
		}
		if r := SourceMapRef(b); len(r) > maxRef || strings.ContainsAny(r, " \t\r\n") {
			t.Fatalf("bad source map ref %q", r)
		}
	})
}

// site is a fake target: path -> answer.
type site map[string]*egress.Answer

func page(body string) *egress.Answer {
	return &egress.Answer{Status: 200, Header: http.Header{}, Body: []byte(body)}
}

func useSite(t *testing.T, s site) *[]string {
	t.Helper()
	var got []string
	oldSend, oldSleep := send, sleep
	send = func(_ context.Context, cfg egress.Config, method, path, _ string, _ []byte, max int64) (*egress.Answer, error) {
		if method != http.MethodGet {
			t.Errorf("method %s", method)
		}
		if max != MaxFileSize {
			t.Errorf("max %d", max)
		}
		got = append(got, path)
		a, ok := s[path]
		switch {
		case !ok:
			return &egress.Answer{Status: 404, Header: http.Header{}}, nil
		case a == nil:
			return nil, errors.New("the target did not answer")
		case a.Status == -1:
			return &egress.Answer{Status: 200, Header: http.Header{}}, egress.ErrTooLarge
		}
		return a, nil
	}
	sleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { send, sleep = oldSend, oldSleep })
	return &got
}

func cfgFor(t *testing.T, raw string) egress.Config {
	t.Helper()
	u, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return egress.Config{Target: u, Version: "test", ReadOnly: true}
}

func TestCollect(t *testing.T) {
	js := page("var k = 1;\n//# sourceMappingURL=app.js.map")
	css := page("a{}")
	css.Header.Set("SourceMap", "/maps/s.css.map")
	got := useSite(t, site{
		"/app/": page(`<script src="app.js"></script><script src="https://cdn.example.com/x.js"></script>
<script src="//other.example/y.js"></script><link rel=stylesheet href="/s.css"><script src="/app/app.js#frag"></script>
<script src="/gone.js"></script><script src="/big.js"></script><script src="/down.js"></script>
<script src="data:text/javascript,alert(1)"></script><link rel=manifest href="/r"><script src="/off"></script>`),
		"/app/app.js":     js,
		"/app/app.js.map": page(`{"sources":[]}`),
		"/s.css":          css,
		"/maps/s.css.map": page("{}"),
		"/big.js":         {Status: -1},
		"/down.js":        nil,
		"/r":              {Status: 302, Header: http.Header{"Location": {"/manifest.json"}}},
		"/manifest.json":  page(`{"name":"x"}`),
		"/off":            {Status: 302, Header: http.Header{"Location": {"https://evil.example/z.js"}}},
	})
	dir := t.TempDir()
	r, err := Collect(context.Background(), cfgFor(t, "http://app.test:8080/app/"), 100, dir)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/app/", "/app/app.js", "/s.css", "/gone.js", "/big.js", "/down.js", "/r", "/manifest.json", "/off", "/app/app.js.map", "/maps/s.css.map"}
	if !slices.Equal(*got, wantPaths) {
		t.Errorf("requests\n%v\nwant\n%v", *got, wantPaths)
	}
	var names, urls []string
	for _, f := range r.Files {
		names, urls = append(names, f.Name), append(urls, f.URL)
		if _, err := os.Stat(filepath.Join(dir, f.Name)); err != nil {
			t.Error(err)
		}
	}
	if want := []string{"001-page.html", "002-script.js", "003-style.css", "004-JSON.json", "005-source-map.map", "006-source-map.map"}; !slices.Equal(names, want) {
		t.Errorf("files %v, want %v", names, want)
	}
	if urls[3] != "http://app.test:8080/manifest.json" || urls[0] != "http://app.test:8080/app/" {
		t.Errorf("urls %v", urls)
	}
	if r.Requests != 10 || r.OtherOrigin != 2 || r.Failed != 3 || r.TooLarge != 1 || r.OverLimit != 0 {
		t.Errorf("result %+v", r)
	}
	want := "scanned 6 file(s): 1 page, 1 script, 1 style, 1 JSON, 2 source maps; not scanned: 2 on another origin, 3 not answered with 200, 1 larger than 10 MiB"
	if s := r.Summary(); s != want {
		t.Errorf("Summary =\n%s\nwant\n%s", s, want)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "002-script.js"))
	if !strings.Contains(string(b), "var k = 1") {
		t.Errorf("script content %q", b)
	}
}

func TestCollectLimit(t *testing.T) {
	var links strings.Builder
	s := site{}
	for i := range MaxRequests + 20 {
		p := "/" + strings.Repeat("a", 1+i%5) + string(rune('a'+i%26)) + "-" + strings.Repeat("x", i/26) + ".js"
		links.WriteString(`<script src="` + p + `"></script>`)
		s[p] = page("x")
	}
	s["/"] = page(links.String())
	got := useSite(t, s)
	r, err := Collect(context.Background(), cfgFor(t, "http://app.test/"), 0, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(*got) != MaxRequests || r.Requests != MaxRequests || len(r.Files) != MaxRequests {
		t.Errorf("sent %d, result %+v files %d", len(*got), r.Requests, len(r.Files))
	}
	if r.OverLimit == 0 {
		t.Errorf("OverLimit = 0")
	}
}

func TestCollectStartPage(t *testing.T) {
	for name, s := range map[string]site{
		"404":     {},
		"down":    {"/": nil},
		"too big": {"/": {Status: -1}},
		"loop":    {"/": {Status: 302, Header: http.Header{"Location": {"/"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			useSite(t, s)
			if _, err := Collect(context.Background(), cfgFor(t, "http://app.test/"), 0, t.TempDir()); err == nil {
				t.Error("no error")
			}
		})
	}
	// A redirect on the same origin is followed for the start page too.
	useSite(t, site{"/": {Status: 301, Header: http.Header{"Location": {"/home"}}}, "/home": page(`<script src="a.js"></script>`), "/a.js": page("x")})
	r, err := Collect(context.Background(), cfgFor(t, "http://app.test/"), 0, t.TempDir())
	if err != nil || len(r.Files) != 2 || r.Files[0].URL != "http://app.test/home" || r.Files[1].URL != "http://app.test/a.js" {
		t.Errorf("redirect: %v %+v", err, r)
	}
}

func TestCollectRate(t *testing.T) {
	useSite(t, site{"/": page(`<script src="/a.js"></script><script src="/b.js"></script>`), "/a.js": page("a"), "/b.js": page("b")})
	var waits []time.Duration
	sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	if _, err := Collect(context.Background(), cfgFor(t, "http://app.test/"), 10, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 2 {
		t.Fatalf("waits %v", waits)
	}
	for _, w := range waits {
		if w > 100*time.Millisecond || w < 90*time.Millisecond {
			t.Errorf("wait %s, want about 100ms at 10 per second", w)
		}
	}
}

func TestCollectCanceled(t *testing.T) {
	useSite(t, site{"/": page(`<script src="/a.js"></script>`), "/a.js": page("a")})
	ctx, cancel := context.WithCancel(context.Background())
	sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	if _, err := Collect(ctx, cfgFor(t, "http://app.test/"), 1, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

func TestFindings(t *testing.T) {
	r := Result{Files: []File{{"001-page.html", "http://app.test/", Page}, {"002-script.js", "http://app.test/app.js", Script}}}
	in := []findings.Finding{
		{RuleID: "github-pat", Message: "GitHub token", Severity: findings.High, Family: "secrets", Location: findings.Location{URI: "002-script.js", StartLine: 3}, Sources: []findings.Source{{Plugin: "gitleaks", RuleID: "github-pat"}}},
		{RuleID: "x", Location: findings.Location{URI: "elsewhere.js"}},
	}
	in[0].ComputeFingerprint()
	before := in[0].Fingerprint
	out := Findings(in, r)
	if len(out) != 1 {
		t.Fatalf("got %d findings", len(out))
	}
	f := out[0]
	if f.Location.URI != "http://app.test/app.js" || f.Location.StartLine != 3 || f.Sources[0].Plugin != ID || f.Fingerprint == before {
		t.Errorf("finding %+v", f)
	}
	if !strings.Contains(f.Message, "script served at http://app.test/app.js") {
		t.Errorf("message %q", f.Message)
	}
	if in[0].Sources[0].Plugin != "gitleaks" {
		t.Error("input changed")
	}
}
