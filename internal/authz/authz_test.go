package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func mustTarget(t *testing.T, raw string) *target.URL {
	t.Helper()
	u, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type entry struct{ method, url string }

func har(t *testing.T, es []entry, headers map[string]string) []byte {
	t.Helper()
	var f harFile
	for _, e := range es {
		var x harEntry
		x.Request.Method, x.Request.URL = e.method, e.url
		for k, v := range headers {
			x.Request.Headers = append(x.Request.Headers, harHeader{k, v})
		}
		f.Log.Entries = append(f.Log.Entries, x)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseHAR(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/app")
	data := har(t, []entry{
		{"GET", "http://localhost:3000/rest/basket/1"},
		{"get", "http://localhost:3000/api/Users/1?x=2"},
		{"GET", "http://localhost:3000/rest/basket/1"},  // duplicate
		{"POST", "http://localhost:3000/api/Feedbacks"}, // other method
		{"HEAD", "http://localhost:3000/"},
		{"GET", "http://localhost:3000/main.js"},           // static
		{"GET", "http://localhost:3000/assets/LOGO.PNG"},   // static
		{"GET", "http://localhost:3001/rest/basket/1"},     // other port
		{"GET", "https://localhost:3000/rest/basket/1"},    // other scheme
		{"GET", "http://evil.test/rest/basket/1"},          // other host
		{"GET", "http://u:p@localhost:3000/rest/basket/1"}, // credentials in the URL
		{"GET", "ws://localhost:3000/socket.io/"},          // not HTTP
		{"GET", "http://localhost:3000//evil.test/x"},      // path not sendable (ADR 0042)
	}, map[string]string{
		"Authorization": "Bearer A", "Cookie": "token=A", "Accept": "application/json",
		":authority": "localhost:3000", "Host": "evil.test", "User-Agent": "Chrome", "Sec-Fetch-Mode": "cors",
		"Proxy-Authorization": "x", "If-None-Match": "W/1", "Content-Length": "3",
	})
	h, err := ParseHAR(data, tu)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range h.Requests {
		paths = append(paths, r.Method+" "+r.Path)
	}
	if !slices.Equal(paths, []string{"GET /rest/basket/1", "GET /api/Users/1?x=2", "HEAD /"}) {
		t.Errorf("requests %v", paths)
	}
	if h.Duplicate != 1 || h.OtherMethod != 1 || h.Static != 2 || h.OtherOrigin != 5 || h.BadPath != 1 || h.OverLimit != 0 {
		t.Errorf("counts %+v", h)
	}
	got := h.Requests[0].Header
	if got.Get("Authorization") != "Bearer A" || got.Get("Cookie") != "token=A" || got.Get("Accept") != "application/json" || len(got) != 3 {
		t.Errorf("headers %v", got)
	}

	for _, c := range []struct{ data, want string }{
		{"not json", "not a HAR file"},
		{`{"log":{"entries":[]}}`, "no requests"},
		{string(har(t, []entry{{"OPTIONS", "http://localhost:3000/x"}, {"GET", "http://localhost:3000/a.js"}}, nil)), "no request to http://localhost:3000 other than static files"},
	} {
		if _, err := ParseHAR([]byte(c.data), tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%.30q: %v, want %q", c.data, err, c.want)
		}
	}

	var many []entry
	for i := range MaxRequests + 5 {
		many = append(many, entry{"GET", fmt.Sprintf("http://localhost:3000/api/x/%d", i)})
	}
	if h, err := ParseHAR(har(t, many, nil), tu); err != nil || len(h.Requests) != MaxRequests || h.OverLimit != 5 {
		t.Errorf("limit: %d requests, %+v %v", len(h.Requests), h.OverLimit, err)
	}
}

func TestParseSession(t *testing.T) {
	h, err := ParseSession("Authorization: Bearer b.c.d\r\n\ncookie: token=B; x=y\n")
	if err != nil || h.Get("Authorization") != "Bearer b.c.d" || h.Get("Cookie") != "token=B; x=y" || len(h) != 2 {
		t.Errorf("%v %v", h, err)
	}
	for _, c := range []struct{ in, want string }{
		{"", "empty"},
		{"\n \n", "empty"},
		{"Bearer x", "one \"Name: value\""},
		{"Bad Name: x", "one \"Name: value\""},
		{"Cookie:", "one \"Name: value\""},
		{"Host: evil.test", "cannot set Host"},
		{"user-agent: x", "cannot set User-Agent"},
		{"Proxy-Authorization: x", "cannot set Proxy-Authorization"},
		{"Cookie: " + strings.Repeat("a", maxSession), "longer than"},
	} {
		if _, err := ParseSession(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%.30q: %v, want %q", c.in, err, c.want)
		}
	}
}

func TestHoldsData(t *testing.T) {
	for body, want := range map[string]bool{
		``:                               false,
		`   `:                            false,
		`null`:                           false,
		`{}`:                             false,
		`[]`:                             false,
		`{"status":"success","data":[]}`: false,
		`{"status":"success","data":{}}`: false,
		`{"ok":true,"message":"done","code":200}`: false,
		`{"data":null,"count":0}`:                 false,
		`{"status":"success","data":[{"id":1}]}`:  true,
		`{"data":{"email":"a@x.test"}}`:           true,
		`{"total":3}`:                             true,
		`[0]`:                                     true,
		`"x"`:                                     true,
		`<html>hello</html>`:                      true,
	} {
		if got := HoldsData([]byte(body)); got != want {
			t.Errorf("%q: %v, want %v", body, got, want)
		}
	}
}

func TestHasID(t *testing.T) {
	for p, want := range map[string]bool{
		"/rest/basket/6":                          true,
		"/api/Users/3?x=1":                        true,
		"/api/orders?id=42":                       true,
		"/a/0f8fad5b-d9cb-469f-a165-70867728950e": true,
		"/a/5f2b9c0e7d3a1b4c":                     true,
		"/api/Users":                              false,
		"/rest/user/whoami":                       false,
		"/a/v2?page=x":                            false,
		"/a/deadbeef":                             false,
	} {
		if got := hasID(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// app is a test app shaped like the Juice Shop measurement (ADR 0035):
// a basket any logged-in account can read by ID, a user list any logged-in
// account can read, a whoami answer that differs per account, an empty
// list, a public product list, and a profile readable with no login.
func app(t *testing.T) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := map[string]string{"Bearer A": "alice@x.test", "Bearer B": "bob@x.test"}[r.Header.Get("Authorization")]
		seen = append(seen, fmt.Sprintf("%s %s %s %s", r.Method, r.URL.RequestURI(), who, r.Header.Get("X-Extra")))
		if !strings.HasPrefix(r.UserAgent(), "SiegeKit/") {
			t.Errorf("user agent %q", r.UserAgent())
		}
		switch r.URL.Path {
		case "/rest/basket/1":
			if who == "" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"status":"success","data":{"id":1,"UserId":1,"Products":[{"name":"Apple"}]}}`)
		case "/api/Users":
			if who == "" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"status":"success","data":[{"email":"alice@x.test"},{"email":"bob@x.test"}]}`)
		case "/rest/user/whoami":
			fmt.Fprintf(w, `{"user":{"email":%q}}`, who)
		case "/api/Cards":
			if who == "" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"status":"success","data":[]}`)
		case "/api/Products":
			fmt.Fprint(w, `{"status":"success","data":[{"name":"Apple"}]}`)
		case "/profile":
			fmt.Fprint(w, `<p>alice@x.test</p>`)
		case "/api/public-users":
			fmt.Fprint(w, `{"data":[{"name":"carol","password":"5f4dcc3b5aa765d61d8327deb882cf99","totp_secret":""}]}`) // gitleaks:allow (fake test value)
		case "/assets/i18n/de.json":
			fmt.Fprint(w, `{"password":"Passwort","secret":"Geheimnis"}`)
		case "/api/me/settings":
			if who == "" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"theme":"dark","language":"en"}`)
		case "/api/settings":
			fmt.Fprint(w, `{"apiKey":"****1234","password":null,"clientSecret":"[redacted]"}`)
		case "/down":
			http.Error(w, "x", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func noSleep(t *testing.T) *[]time.Duration {
	var waits []time.Duration
	old, oldNow, start := sleep, now, time.Now()
	sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	now = func() time.Time { return start }
	t.Cleanup(func() { sleep, now = old, oldNow })
	return &waits
}

func TestCheck(t *testing.T) {
	srv, seen := app(t)
	waits := noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	var es []entry
	for _, p := range []string{"/rest/basket/1", "/api/Users", "/rest/user/whoami", "/api/Cards", "/api/Products", "/profile", "/api/public-users", "/assets/i18n/de.json", "/api/settings", "/api/me/settings", "/down"} {
		es = append(es, entry{"GET", srv.URL + p})
	}
	h, err := ParseHAR(har(t, es, map[string]string{"Authorization": "Bearer A", "X-Extra": "kept"}), tu)
	if err != nil {
		t.Fatal(err)
	}
	b := http.Header{"Authorization": {"Bearer B"}}
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{B: b}, 10)
	if err != nil {
		t.Fatal(err)
	}
	// 10 requests answered A with 2xx and were sent three times; /down once;
	// /rest/user/whoami once more as A, because B's answer lines up with
	// A's word by word (Replay.Again, issue #95).
	if res.ATried != 11 || res.AFailed != 1 || res.Requests != 32 || len(*seen) != 32 || res.BRefused != 0 || !res.BTested {
		t.Errorf("%+v", res)
	}
	if len(*waits) != 31 || (*waits)[0] != 100*time.Millisecond {
		t.Errorf("waits %v", *waits)
	}
	// A's own headers stay for B and no login; only the session changes.
	if (*seen)[0] != "GET /rest/basket/1 alice@x.test kept" || (*seen)[1] != "GET /rest/basket/1 bob@x.test kept" || (*seen)[2] != "GET /rest/basket/1  kept" {
		t.Errorf("sent %q", (*seen)[:3])
	}
	fs := Findings(srv.URL, res, "alice@x.test")
	var got []string
	for _, f := range fs {
		got = append(got, f.RuleID+" "+f.Location.URI[len(srv.URL):]+" "+f.CWEs[0]+" "+f.Severity.String())
		if f.Fingerprint == "" || f.Sources[0].Plugin != ID || strings.Contains(f.Message, "alice") || strings.Contains(f.Message, "Apple") || strings.Contains(f.Message, "5f4d") {
			t.Errorf("%+v", f)
		}
	}
	// High with an ID in the URL or A's login name in the answer; the
	// same default settings for every account and no-login reads are
	// medium (ADR 0035).
	want := []string{"cross-account-read /rest/basket/1 CWE-639 high", "cross-account-read /api/Users CWE-862 high", "no-login-read /profile CWE-306 medium",
		"no-login-secret /api/public-users CWE-200 high", "cross-account-read /api/me/settings CWE-862 medium"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	if c := Count(res, "alice@x.test"); c != (Counts{Cross: 3, NoLogin: 1, Secrets: 1}) {
		t.Errorf("count %+v", c)
	}
	if s := res.Summary(h, "alice@x.test", Count(res, "alice@x.test")); s != "replayed 11 request(s) from the HAR file: 3 readable by account B; account C not tested (SIEGEKIT_SESSION_C not set), 1 readable with no login, 1 with secret fields for no login; 1 did not answer account A with 2xx and were not sent further" {
		t.Errorf("summary %q", s)
	}
	// Without --har-user, no-login reads are not reported.
	if fs := Findings(srv.URL, res, ""); len(fs) != 4 || fs[1].Severity != findings.Medium {
		t.Errorf("%d findings without a login name", len(fs))
	}
	if s := res.Summary(&HAR{Static: 3}, "", Counts{Cross: 2}); !strings.Contains(s, "no-login reads not reported") || !strings.HasSuffix(s, "3 static files not replayed") {
		t.Errorf("summary %q", s)
	}
}

func TestCheckWithoutB(t *testing.T) {
	srv, seen := app(t)
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	h, err := ParseHAR(har(t, []entry{{"GET", srv.URL + "/rest/basket/1"}, {"GET", srv.URL + "/profile"}}, map[string]string{"Authorization": "Bearer A"}), tu)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{}, 10)
	if err != nil || res.BTested || len(*seen) != 4 {
		t.Fatalf("%+v %v %v", res, err, *seen)
	}
	fs := Findings(srv.URL, res, "alice@x.test")
	if len(fs) != 1 || fs[0].RuleID != "no-login-read" {
		t.Errorf("%+v", fs)
	}
	if s := res.Summary(h, "alice@x.test", Counts{NoLogin: 1}); !strings.Contains(s, "accounts B and C not tested") {
		t.Errorf("summary %q", s)
	}
}

func TestCheckBRefused(t *testing.T) {
	srv, _ := app(t)
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	h, _ := ParseHAR(har(t, []entry{{"GET", srv.URL + "/rest/basket/1"}}, map[string]string{"Authorization": "Bearer A"}), tu)
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{B: http.Header{"Authorization": {"Bearer expired"}}}, 10)
	if err != nil || res.BRefused != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if s := res.Summary(h, "", Counts{}); !strings.Contains(s, "refused on every request") {
		t.Errorf("summary %q", s)
	}
	if fs := Findings(srv.URL, res, ""); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
}

func TestCheckRefusesWritableConfig(t *testing.T) {
	if _, err := Check(context.Background(), egress.Config{}, []Request{{Method: "GET", Path: "/"}}, Accounts{}, 1); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("%v", err)
	}
}

func TestCheckStopsWhenCancelled(t *testing.T) {
	srv, _ := app(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	ctx, cancel := context.WithCancel(context.Background())
	old := sleep
	sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	t.Cleanup(func() { sleep = old })
	_, err := Check(ctx, cfg, []Request{{Method: "GET", Path: "/rest/basket/1"}, {Method: "GET", Path: "/api/Users"}}, Accounts{}, 1)
	if err == nil {
		t.Error("not stopped")
	}
}

func FuzzParseHAR(f *testing.F) {
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/a/1","headers":[{"name":"Cookie","value":"x"}]}}]}}`), "Cookie: a\nAuthorization: b")
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"HEAD","url":"http://localhost:3000"}}]}}`), "")
	tu, err := target.Parse("http://localhost:3000/")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte, session string) {
		if h, err := ParseHAR(data, tu); err == nil {
			if len(h.Requests)+len(h.Recorded) == 0 || len(h.Requests) > MaxRequests || len(h.Recorded) > MaxRecorded {
				t.Fatalf("%d requests, %d recorded", len(h.Requests), len(h.Recorded))
			}
			for _, x := range h.Recorded {
				if !recordMethods[x.Method] || !strings.HasPrefix(x.URL, "http://localhost:3000/") || x.Body == "" && (x.MimeType != "" || x.Header.Get("Content-Type") != "") || x.Header.Get("Host") != "" {
					t.Fatalf("%+v", x)
				}
			}
			for _, r := range h.Requests {
				if r.Method != "GET" && r.Method != "HEAD" || !strings.HasPrefix(r.Path, "/") || r.Header.Get("Host") != "" || r.Header.Get("User-Agent") != "" {
					t.Fatalf("%+v", r)
				}
			}
		}
		if h, err := ParseSession(session); err == nil {
			for k, vs := range h {
				if skipHeaders[k] || strings.HasPrefix(k, "Proxy-") || len(vs) == 0 {
					t.Fatalf("%v", h)
				}
			}
		}
	})
}

func TestSpecRoutes(t *testing.T) {
	spec := "\xef\xbb\xbf" + `{"openapi":"3.0.3","paths":{
		"/users":{"get":{}},"/users/{id}":{"get":{}},"/orders":{"post":{}},"/me":{"get":{},"put":{}},
		"relative":{"get":{}},"//evil.test/x":{"get":{}},"/a?b":{"get":{}},"/a b":{"get":{}}}}`
	if got := SpecRoutes([]byte(spec), "json"); !slices.Equal(got, []string{"/me", "/users"}) {
		t.Errorf("%v", got)
	}
	if got := SpecRoutes([]byte("paths:\n  /users:\n    get: {}\n"), "yaml"); got != nil {
		t.Errorf("yaml: %v", got)
	}
	if got := SpecRoutes([]byte("{"), "json"); got != nil {
		t.Errorf("broken: %v", got)
	}

	h := &HAR{Requests: []Request{
		{Method: "GET", Path: "/api/me", Header: http.Header{"Authorization": {"Bearer A"}, "Accept": {"x"}}},
		{Method: "GET", Path: "/api/cart", Header: http.Header{"Cookie": {"s=A"}, "Accept": {"x"}}},
		{Method: "GET", Path: "/", Header: http.Header{"Accept": {"x"}}},
	}}
	h.AddSpecRoutes([]string{"/me", "/users"}, "/api")
	if len(h.Requests) != 4 || h.FromSpec != 1 || h.Requests[3].Path != "/api/users" || h.Requests[3].Header.Get("Cookie") != "s=A" || h.Requests[3].Header.Get("Accept") != "x" || len(h.Requests[3].Header) != 2 {
		t.Errorf("%+v", h)
	}
	// Every header of A's last session request goes with it, not only the
	// session ones, as a copy (ADR 0052).
	h.Requests[3].Header.Set("Accept", "changed")
	if h.Requests[1].Header.Get("Accept") != "x" {
		t.Error("spec route shares A's header map")
	}
	none := &HAR{Requests: []Request{{Method: "GET", Path: "/", Header: http.Header{"Accept": {"x"}}}}}
	if none.AddSpecRoutes([]string{"/users"}, ""); len(none.Requests) != 1 || none.FromSpec != 0 {
		t.Errorf("no session: %+v", none)
	}
	full := &HAR{}
	for i := range MaxRequests {
		full.Requests = append(full.Requests, Request{Method: "GET", Path: fmt.Sprintf("/%d", i), Header: http.Header{"Authorization": {"x"}}})
	}
	if full.AddSpecRoutes([]string{"/a", "/b"}, ""); len(full.Requests) != MaxRequests || full.OverLimit != 2 {
		t.Errorf("limit: %d %d", len(full.Requests), full.OverLimit)
	}
}

func TestSecretFields(t *testing.T) {
	for body, want := range map[string]string{
		`{"data":[{"User":{"email":"a","password":"0192023a7bbd73250516f069df18b500","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","totpSecret":""}}]}`: "deluxeToken password", // gitleaks:allow (fake test value)
		`{"identityProviders":[{"config":{"oauth2Config":{"clientId":"cid","client_secret":"csecret-abcdef123456"}}}]}`:                                                                    "client_secret",        // gitleaks:allow (fake test value)
		`{"cardNumber":4111111111111111,"cvv":123}`:                             "cardNumber cvv",
		`{"password":"","password_min_length":12,"secret":false,"apiKey":null}`: "",
		`{"password":"********","apiKey":"****1234","token":"abcdef123456"}`:    "", // gitleaks:allow (fake test value)
		`{"password":"Enter your password","secret":"redacted","pwd":"xxxx"}`:   "",
		`{"LABEL_PASSWORD":"Password","passwordHint":"abc123"}`:                 "",
		`not json`: "",
		`{"a":{"b":{"c":{"d":{"e":{"f":{"Password":"hunter2"}}}}}}}`: "Password",
	} {
		if got := strings.Join(SecretFields([]byte(body)), " "); got != want {
			t.Errorf("%.40s: %q, want %q", body, got, want)
		}
	}
	var many strings.Builder
	many.WriteString("{")
	for i, k := range []string{"password", "salt", "secret", "apiKey", "ssn", "cvv", "pwd"} {
		if i > 0 {
			many.WriteString(",")
		}
		fmt.Fprintf(&many, "%q:%q", k, "v4lue"+k)
	}
	many.WriteString("}")
	if got := SecretFields([]byte(many.String())); len(got) != 5 {
		t.Errorf("%v", got)
	}
}

// TestParseHARRecorded checks which recorded requests are kept for ZAP's
// attack scan (ADR 0047): GET, HEAD, POST, PUT, PATCH and DELETE on the
// target's origin, static files left out, without duplicates.
func TestParseHARRecorded(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	e := func(method, u, mime, body string, hs ...harHeader) harEntry {
		var x harEntry
		x.Request.Method, x.Request.URL, x.Request.Headers = method, u, hs
		if body != "" || mime != "" {
			x.Request.PostData = &harPostData{MimeType: mime, Text: body}
		}
		return x
	}
	var f harFile
	f.Log.Entries = []harEntry{
		e("POST", "http://localhost:3000/api/order", "application/xml", "<order/>", harHeader{"Cookie", "s=A"}, harHeader{"Content-Length", "8"}),
		e("POST", "http://localhost:3000/api/order", "application/xml", "<order/>"),                      // duplicate
		e("POST", "http://localhost:3000/api/order", "application/xml", "<order n=\"2\"/>"),              // another body
		e("PUT", "http://localhost:3000/soap?v=2", "application/soap+xml; charset=utf-8", "<Envelope/>"), // query kept
		e("POST", "http://localhost:3000/json", "application/json", `{"a":1}`),
		e("POST", "http://localhost:3000/empty", "application/xml", "", harHeader{"Content-Type", "text/xml"}), // no body: no type
		e("DELETE", "http://localhost:3000/x", "", ""),
		e("OPTIONS", "http://localhost:3000/x", "", ""),                                           // other method
		e("POST", "http://localhost:3001/x", "application/xml", "<a/>"),                           // other origin
		e("POST", "http://localhost:3000//evil.test/x", "application/xml", "<a/>"),                // path not sendable
		e("POST", "http://localhost:3000/hdr", "", "<a/>", harHeader{"content-type", "text/xml"}), // type from the header
		e("GET", "http://localhost:3000/main.js", "", ""),                                         // static
		e("GET", "http://localhost:3000/page", "", ""),
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHAR(data, tu)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range h.Recorded {
		got = append(got, x.Method+" "+x.URL+" "+x.Header.Get("Content-Type"))
	}
	want := []string{
		"POST http://localhost:3000/api/order application/xml",
		"POST http://localhost:3000/api/order application/xml",
		"PUT http://localhost:3000/soap?v=2 application/soap+xml; charset=utf-8",
		"POST http://localhost:3000/json application/json",
		"POST http://localhost:3000/empty ",
		"DELETE http://localhost:3000/x ",
		"POST http://localhost:3000/hdr text/xml",
		"GET http://localhost:3000/page ",
	}
	if !slices.Equal(got, want) {
		t.Errorf("recorded requests\n%v\nwant\n%v", got, want)
	}
	if x := h.Recorded[0]; x.Header.Get("Cookie") != "s=A" || x.Header.Get("Content-Length") != "" || x.Body != "<order/>" {
		t.Errorf("first: %+v", x)
	}
	if len(h.Requests) != 1 || h.Static != 1 || h.OtherOrigin != 1 || h.BadPath != 1 {
		t.Errorf("replay %d, counts %+v", len(h.Requests), h)
	}

	// A recording with no GET or HEAD request is accepted.
	f.Log.Entries = f.Log.Entries[:1]
	data, _ = json.Marshal(f)
	if h, err := ParseHAR(data, tu); err != nil || len(h.Requests) != 0 || len(h.Recorded) != 1 {
		t.Errorf("POST only: %+v %v", h, err)
	}
	var many harFile
	for i := range MaxRecorded + 3 {
		many.Log.Entries = append(many.Log.Entries, e("POST", fmt.Sprintf("http://localhost:3000/x/%d", i), "text/xml", "<a/>"))
	}
	data, _ = json.Marshal(many)
	if h, err := ParseHAR(data, tu); err != nil || len(h.Recorded) != MaxRecorded || h.RecordedOverLimit != 3 {
		t.Errorf("limit: %d %d %v", len(h.Recorded), h.RecordedOverLimit, err)
	}
}

// TestCheckPrefetch: a Next.js router prefetch of a route's loading
// boundary (Next-Router-Prefetch: 1) is the same for every account and is
// not compared; a runtime prefetch (2) and an RSC request are (issue #96).
func TestCheckPrefetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprintf(w, `0:{"b":"build","tree":["w",{"children":["__PAGE__",{}]}],"q":%q}`, r.URL.RawQuery)
	}))
	defer srv.Close()
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	var f harFile
	for q, pf := range map[string]string{"_rsc=a": "1", "_rsc=b": "2", "_rsc=c": ""} {
		var x harEntry
		x.Request.Method, x.Request.URL = "GET", srv.URL+"/w?"+q
		x.Request.Headers = []harHeader{{"Authorization", "Bearer A"}, {"RSC", "1"}}
		if pf != "" {
			x.Request.Headers = append(x.Request.Headers, harHeader{"Next-Router-Prefetch", pf})
		}
		f.Log.Entries = append(f.Log.Entries, x)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHAR(b, tu)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{C: http.Header{"Authorization": {"Bearer C"}}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.Replays {
		if r.Outsider() {
			got = append(got, r.Path)
		}
	}
	slices.Sort(got)
	if want := []string{"/w?_rsc=b", "/w?_rsc=c"}; !slices.Equal(got, want) {
		t.Errorf("read by C: %q, want %q", got, want)
	}
	if s := res.Summary(h, "", Count(res, "")); !strings.Contains(s, "; 1 Next.js router prefetch(es) (Next-Router-Prefetch: 1) not compared") {
		t.Errorf("summary %q", s)
	}
}
