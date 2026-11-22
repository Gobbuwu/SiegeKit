package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// writeEntry is one HAR entry with a body and an answer.
type writeEntry struct {
	method, url, mime, body string
	status                  int
	answer                  string
	headers                 map[string]string
}

func writeHAR(t *testing.T, es []writeEntry) []byte {
	t.Helper()
	type hdr struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var f struct {
		Log struct {
			Entries []map[string]any `json:"entries"`
		} `json:"log"`
	}
	for _, e := range es {
		var hs []hdr
		for k, v := range e.headers {
			hs = append(hs, hdr{k, v})
		}
		req := map[string]any{"method": e.method, "url": e.url, "headers": hs}
		if e.body != "" || e.mime != "" {
			req["postData"] = map[string]any{"mimeType": e.mime, "text": e.body}
		}
		f.Log.Entries = append(f.Log.Entries, map[string]any{
			"request":  req,
			"response": map[string]any{"status": e.status, "content": map[string]any{"mimeType": "application/json", "text": e.answer}},
		})
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeApp is a small app shaped like what was measured on Juice Shop
// (ADR 0049): basket items any logged-in account can change or delete,
// one item per product per owner (a second create is refused), cards that
// check their owner and share ID numbers with the items, notes each
// account makes for itself, and a form that needs the session's CSRF
// token. Requests with no login are refused.
func writeApp(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	type item struct {
		owner   string
		product int
		qty     int
	}
	items, cards := map[int]*item{}, map[int]string{}
	nextItem, nextCard := 7, 7
	who := func(r *http.Request) string {
		return map[string]string{"Bearer A": "alice", "Bearer B": "bob"}[r.Header.Get("Authorization")]
	}
	mux := http.NewServeMux()
	logged := func(h func(w http.ResponseWriter, r *http.Request, u string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			u := who(r)
			seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+u)
			if u == "" {
				http.Error(w, `{"error":"log in"}`, http.StatusUnauthorized)
				return
			}
			h(w, r, u)
		}
	}
	mux.HandleFunc("POST /api/items/", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		var in struct{ Product, Qty int }
		json.NewDecoder(r.Body).Decode(&in)
		for _, it := range items {
			if it.owner == u && it.product == in.Product {
				http.Error(w, `{"error":"already in basket"}`, http.StatusBadRequest)
				return
			}
		}
		id := nextItem
		nextItem++
		items[id] = &item{u, in.Product, in.Qty}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","data":{"id":%d,"ProductId":%d,"quantity":%d}}`, id, in.Product, in.Qty)
	}))
	mux.HandleFunc("GET /api/items/{id}", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		it, ok := items[id]
		if !ok || it.owner != u {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"data":{"id":%d,"quantity":%d}}`, id, it.qty)
	}))
	mux.HandleFunc("PUT /api/items/{id}", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		it, ok := items[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		var in struct{ Quantity int }
		json.NewDecoder(r.Body).Decode(&in)
		it.qty = in.Quantity // no owner check
		fmt.Fprint(w, `{"status":"success"}`)
	}))
	mux.HandleFunc("DELETE /api/items/{id}", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		if _, ok := items[id]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(items, id) // no owner check
		fmt.Fprint(w, `{"status":"success"}`)
	}))
	mux.HandleFunc("POST /api/cards/", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id := nextCard
		nextCard++
		cards[id] = u
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","data":{"id":%d}}`, id)
	}))
	mux.HandleFunc("GET /api/cards/{id}", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		if cards[id] != u {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"data":{"id":%d}}`, id)
	}))
	mux.HandleFunc("DELETE /api/cards/{id}", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		if cards[id] != u {
			http.Error(w, `{"error":"not yours"}`, http.StatusForbidden)
			return
		}
		delete(cards, id)
		fmt.Fprint(w, `{"status":"success"}`)
	}))
	mux.HandleFunc("POST /api/notes", logged(func(w http.ResponseWriter, r *http.Request, u string) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"status":"success"}`)
	}))
	// A page gives its viewer a CSRF token: logged-in accounts in a script
	// value (as Gitea's start page does), anyone else in a meta tag with a
	// cookie that holds it.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, "GET / "+who(r))
		if u := who(r); u != "" {
			fmt.Fprintf(w, "<script>window.config = {csrfToken: 'tok-%s-0123456789'};</script>", u)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "_csrf", Value: "anon1"})
		fmt.Fprint(w, `<meta name="_csrf" content="tok-anon1">`)
	})
	// An organisation's settings form: any logged-in account with its own
	// CSRF token may change it (the planted flaw); a success redirects back
	// with 303, as server-rendered forms do; no login redirects to /login.
	settings := map[string]string{}
	mux.HandleFunc("POST /orgs/{id}/settings", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		u := who(r)
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+u)
		r.ParseForm()
		c, _ := r.Cookie("_csrf")
		switch {
		case u == "" && (c == nil || r.PostForm.Get("_csrf") != "tok-"+c.Value):
			http.Error(w, "bad csrf", http.StatusBadRequest)
		case u == "":
			http.Redirect(w, r, "/login?next=/orgs", http.StatusSeeOther)
		case r.PostForm.Get("_csrf") != "tok-"+u+"-0123456789":
			http.Error(w, "bad csrf", http.StatusBadRequest)
		default:
			settings[r.PathValue("id")] = r.PostForm.Get("name")
			http.Redirect(w, r, "/orgs/"+r.PathValue("id")+"/settings", http.StatusSeeOther)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// A's recorded state, as in the Juice Shop recording: A deleted item 7
	// (product 1) at the end, and card 7 is still there.
	cards[7] = "alice"
	nextItem, nextCard = 8, 8
	return srv, &seen
}

func TestParseWrites(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	a := map[string]string{"Authorization": "Bearer A", "Content-Type": "application/json"}
	data := writeHAR(t, []writeEntry{
		{method: "POST", url: "http://localhost:3000/rest/user/login", mime: "application/json", body: `{"email":"a"}`, status: 200, answer: `{"authentication":{"token":"x","id":1}}`},
		{method: "GET", url: "http://localhost:3000/api/items/1", status: 200, answer: `{"id":7}`, headers: a},
		{method: "POST", url: "http://localhost:3000/api/items/", mime: "application/json", body: `{"Product":1,"Qty":1}`, status: 201, answer: `{"status":"success","data":{"id":7,"ProductId":1}}`, headers: a},
		{method: "PUT", url: "http://localhost:3000/api/items/7", mime: "application/json", body: `{"Quantity":2}`, status: 200, headers: a},
		{method: "POST", url: "http://localhost:3000/api/cards/", mime: "application/json", body: `{}`, status: 201, answer: `{"data":{"id":7}}`, headers: a},
		// After the card got ID 7 too, the item's create is still taken.
		{method: "DELETE", url: "http://localhost:3000/api/items/7", status: 200, headers: a},
		{method: "DELETE", url: "http://localhost:3000/api/cards/7", status: 200, headers: a},
		{method: "PUT", url: "http://localhost:3000/api/items/7", mime: "application/json", body: `{"Quantity":2}`, status: 200, headers: a}, // duplicate
		{method: "POST", url: "http://localhost:3000/settings", mime: "application/x-www-form-urlencoded", body: "_csrf=tok-alice&name=A", status: 200, headers: map[string]string{"Authorization": "Bearer A"}},
		{method: "POST", url: "http://localhost:3000/upload", mime: "multipart/form-data", status: 200},                                 // params only
		{method: "POST", url: "http://localhost:3001/api/items/", mime: "application/json", body: "{}", status: 201},                    // other origin
		{method: "PATCH", url: "http://localhost:3000/api/users/me/password", mime: "application/json", body: "{}", status: 200},        // lockout
		{method: "DELETE", url: "http://localhost:3000/api/Users/26", status: 200},                                                      // deletes an account
		{method: "POST", url: "http://localhost:3000/api/2fa/setup", mime: "application/json", body: "{}", status: 200},                 // lockout
		{method: "POST", url: "http://localhost:3000/api/items/", mime: "application/json", body: `{"Product":2,"Qty":1}`, status: 400}, // refused for A: no IDs
	})
	// The multipart entry has params but no text.
	var f map[string]any
	json.Unmarshal(data, &f)
	entries := f["log"].(map[string]any)["entries"].([]any)
	entries[9].(map[string]any)["request"].(map[string]any)["postData"] = map[string]any{"mimeType": "multipart/form-data", "params": []any{map[string]any{"name": "f"}}}
	data, _ = json.Marshal(f)

	w, err := ParseWrites(data, tu)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range w.Writes {
		s := x.Method + " " + x.Path
		if x.Create != nil {
			s += fmt.Sprintf(" <- %s %v=%s", x.Create.Path, x.Create.Field, x.Create.OldID)
		}
		if x.CSRF {
			s += " csrf"
		}
		if x.Tried {
			s += " tried " + string(x.Body)
		}
		got = append(got, s)
	}
	// The recording never used PATCH on items, nor PUT or PATCH on cards:
	// SiegeKit tries them on copies, with A's create body.
	want := []string{
		"POST /api/items/",
		"PUT /api/items/7 <- /api/items/ [data id]=7",
		"POST /api/cards/",
		"DELETE /api/items/7 <- /api/items/ [data id]=7",
		"DELETE /api/cards/7 <- /api/cards/ [data id]=7",
		"POST /settings csrf",
		"POST /api/items/",
		`PATCH /api/items/7 <- /api/items/ [data id]=7 tried {"Product":1,"Qty":1}`,
		`PUT /api/cards/7 <- /api/cards/ [data id]=7 tried {}`,
		`PATCH /api/cards/7 <- /api/cards/ [data id]=7 tried {}`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("writes\n%q\nwant\n%q", got, want)
	}
	if w.Lockout != 4 || !slices.Equal(w.LockoutPaths, []string{"POST /rest/user/login", "PATCH /api/users/me/password", "DELETE /api/Users/26", "POST /api/2fa/setup"}) || w.NoBody != 1 || w.Duplicate != 1 || w.OverLimit != 0 {
		t.Errorf("%+v", w)
	}
	if w.Writes[1].Header.Get("Content-Type") != "application/json" || string(w.Writes[1].Body) != `{"Quantity":2}` || w.Writes[3].Header.Get("Content-Type") != "" {
		t.Errorf("%+v", w.Writes[1])
	}
	if _, err := ParseWrites([]byte("{"), tu); err == nil {
		t.Error("bad HAR accepted")
	}
}

func TestParseWritesLimit(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	var es []writeEntry
	for i := 0; i < MaxWrites+3; i++ {
		es = append(es, writeEntry{method: "DELETE", url: fmt.Sprintf("http://localhost:3000/api/items/%d", i), status: 200})
	}
	w, err := ParseWrites(writeHAR(t, es), tu)
	if err != nil || len(w.Writes) != MaxWrites || w.OverLimit != 3 {
		t.Fatalf("%d writes, %d over, %v", len(w.Writes), w.OverLimit, err)
	}
}

func TestLockoutReason(t *testing.T) {
	for p, want := range map[string]string{
		"POST /rest/user/login":                "its path names login",
		"POST /user/logout":                    "its path names logout",
		"POST /api/signOut":                    "its path names signout",
		"POST /accounts/sign-up":               "its path names signup",
		"PUT /rest/user/change-password":       "its path names password",
		"POST /rest/2fa/setup":                 "its path names 2fa",
		"POST /api/TwoFactor/enable":           "its path names twofactor",
		"POST /api/v1/users/alice/tokens":      "its path names tokens",
		"DELETE /api/sessions/3":               "its path names sessions",
		"POST /api/keys?action=resetPassword":  "its query names password",
		"DELETE /api/Users/26":                 "it deletes an account",
		"DELETE /api/me":                       "it deletes an account",
		"DELETE /user/starred/alice/pub":       "",
		"PUT /api/BasketItems/9":               "",
		"PATCH /repos/alice/pub/issues/1":      "",
		"POST /rest/products/1/reviews":        "",
		"DELETE /api/Addresss/7":               "",
		"POST /api/feedback?token_type=bearer": "its query names token",
	} {
		m, path, _ := strings.Cut(p, " ")
		if got := lockoutReason(m, path); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestToLogin(t *testing.T) {
	for loc, want := range map[string]bool{
		"": true, "/user/login?redirect_to=%2F": true, "https://app.test/signIn": true, "/auth/realms/x": true, "/users/sign_in": true,
		"/orgs/3/settings": false, "/alice/pub": false, "/": false, "/blog/authors": false,
	} {
		if got := toLogin(loc); got != want {
			t.Errorf("%q: %v", loc, got)
		}
	}
}

func TestEchoed(t *testing.T) {
	for _, c := range []struct {
		loc, sent, body string
		want            bool
	}{
		{"/alice/pub/issues/1", "/-/fetch-redirect", "redirect=%2Falice%2Fpub%2Fissues%2F1", true},
		{"http://app.test/next", "/go?to=http%3A%2F%2Fapp.test%2Fnext", "", true},
		{"/orgs/3/settings", "/orgs/3/settings", "_csrf=x&name=A", false},
		{"/alice/pub", "/repo/create", "uid=1&repo_name=pub", false},
		{"", "/x", "a=b", false},
	} {
		if got := echoed(c.loc, c.sent, []byte(c.body)); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestWithID(t *testing.T) {
	w := Write{Method: "PATCH", Path: "/api/items/7/notes?item=7&q=7x", Header: http.Header{"Content-Type": {"application/json"}},
		Body: []byte(`{"id":7,"BasketId":"7","quantity":7,"note":"7","nested":{"item_id":7}}`)}
	got := w.withID("7", "12")
	if got.Path != "/api/items/12/notes?item=12&q=7x" {
		t.Errorf("path %q", got.Path)
	}
	var b map[string]any
	json.Unmarshal(got.Body, &b)
	if b["id"] != float64(12) || b["BasketId"] != "12" || b["quantity"] != float64(7) || b["note"] != "7" || b["nested"].(map[string]any)["item_id"] != float64(12) {
		t.Errorf("body %s", got.Body)
	}
	if string(w.Body) == string(got.Body) || w.Path == got.Path {
		t.Error("the recorded write changed")
	}
	f := Write{Method: "POST", Path: "/x", Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, Body: []byte("item_id=7&count=7")}
	if got := string(f.withID("7", "9").Body); got != "count=7&item_id=9" {
		t.Errorf("form %q", got)
	}
}

func TestPlainCreate(t *testing.T) {
	for _, c := range []struct {
		w    Write
		want bool
	}{
		{Write{Method: "POST", Path: "/api/Addresss/", Body: []byte(`{"city":"x","mobileNum":1234567}`)}, true},
		{Write{Method: "POST", Path: "/api/BasketItems/", Body: []byte(`{"ProductId":1,"BasketId":"6"}`)}, false},
		{Write{Method: "POST", Path: "/rest/basket/6/checkout", Body: []byte(`{}`)}, false},
		{Write{Method: "POST", Path: "/repos/alice/priv/issues", Body: []byte(`{"title":"x"}`)}, false},
		{Write{Method: "POST", Path: "/repos/carol/priv/issues", Body: []byte(`{"title":"x"}`)}, true},
		{Write{Method: "POST", Path: "/f", Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, Body: []byte("repo_id=3")}, false},
		{Write{Method: "PUT", Path: "/api/x", Body: []byte(`{}`)}, false},
	} {
		if got := plainCreate(c.w, "Alice"); got != c.want {
			t.Errorf("%s %s: %v", c.w.Method, c.w.Path, got)
		}
	}
}

func appWrites(t *testing.T, srv *httptest.Server) *Writes {
	t.Helper()
	a := map[string]string{"Authorization": "Bearer A", "Content-Type": "application/json"}
	w, err := ParseWrites(writeHAR(t, []writeEntry{
		{method: "POST", url: srv.URL + "/api/items/", mime: "application/json", body: `{"Product":1,"Qty":1}`, status: 201, answer: `{"status":"success","data":{"id":7}}`, headers: a},
		{method: "PUT", url: srv.URL + "/api/items/7", mime: "application/json", body: `{"Quantity":5}`, status: 200, headers: a},
		{method: "POST", url: srv.URL + "/api/cards/", mime: "application/json", body: `{}`, status: 201, answer: `{"data":{"id":7}}`, headers: a},
		{method: "DELETE", url: srv.URL + "/api/items/7", status: 200, headers: a},
		{method: "DELETE", url: srv.URL + "/api/cards/7", status: 200, headers: a},
		{method: "POST", url: srv.URL + "/api/notes", mime: "application/json", body: `{"text":"x"}`, status: 201, headers: a},
		{method: "POST", url: srv.URL + "/orgs/3/settings", mime: "application/x-www-form-urlencoded", body: "_csrf=tok-alice-0123456789&name=A", status: 303, headers: map[string]string{"Authorization": "Bearer A"}},
		{method: "POST", url: srv.URL + "/logout", status: 200, headers: a},
	}), mustTarget(t, srv.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWriteCheck(t *testing.T) {
	srv, seen := writeApp(t)
	waits := noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	w := appWrites(t, srv)
	res, err := WriteCheck(context.Background(), cfg, w.Writes, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range WriteFindings(srv.URL, res) {
		got = append(got, f.RuleID+" "+strings.TrimPrefix(f.Location.URI, srv.URL)+" "+f.CWEs[0]+" "+f.Severity.String())
		if f.Fingerprint == "" || f.Sources[0].Plugin != WriteID || f.Family != Family {
			t.Errorf("%+v", f)
		}
	}
	// B changes and deletes A's item (high: A's read changed). The card
	// checks its owner; A's own creates are B's own when B sends them
	// (plain creates, not sent as B); logout is never sent.
	// B also changes organisation 3's settings with its own CSRF token,
	// answered with a redirect like A's recorded write (medium: a POST).
	want := []string{"cross-account-write /api/items/7 CWE-639 high", "cross-account-write /api/items/7 CWE-639 high", "cross-account-write /orgs/3/settings CWE-639 medium"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for _, s := range *seen {
		if strings.Contains(s, "/logout") || strings.HasPrefix(s, "POST /api/notes") && strings.HasSuffix(s, "bob") {
			t.Errorf("sent %q", s)
		}
	}
	// Every replay on an item or card worked on a copy A made first, and
	// A deleted the copies that were left; A's recorded item and card are
	// untouched.
	for _, r := range res.Replays {
		if strings.Contains(r.Path, "/7") && (!r.Recreated || r.Sent == r.Path) {
			t.Errorf("not on a copy: %+v", r)
		}
	}
	// B fetched its own CSRF token for the form and changed A's
	// organisation (a redirect, as A's recorded write got), so the request
	// with no login is not sent on that recorded object.
	for _, r := range res.Replays {
		if pathOf(r.Path) == "/orgs/3/settings" && (r.Who == AsB && (!r.CSRFSwapped || r.Answer.Status != http.StatusSeeOther || !r.Accepted()) || r.Who == AsNoLogin && r.NotSent == "") {
			t.Errorf("form replay %+v", r)
		}
	}
	// Items 8 to 11 and cards 8 and 9 for the recorded writes, and 6 more
	// for the tries (PATCH on items, PUT and PATCH on cards, which the app
	// refuses); all but the one B deleted are deleted again by A.
	if res.Recreated != 12 || res.CleanedUp != 11 {
		t.Errorf("recreated %d, cleaned up %d", res.Recreated, res.CleanedUp)
	}
	a := http.Header{"Authorization": {"Bearer A"}}
	for p, want := range map[string]int{"/api/cards/7": 200, "/api/cards/8": 404, "/api/cards/9": 404, "/api/items/8": 404, "/api/items/9": 404, "/api/items/10": 404, "/api/items/11": 404} {
		if ans, err := egress.SendHeader(context.Background(), cfg, "GET", p, a, nil, 1<<10); err != nil || ans.Status != want {
			t.Errorf("A's %s: %v %v, want %d", p, ans, err, want)
		}
	}
	if len(*waits) != res.Requests-1 {
		t.Errorf("%d waits for %d requests", len(*waits), res.Requests)
	}
	s := res.WriteSummary(w)
	for _, part := range []string{
		"replayed 7 write(s) from the HAR file and 3 not in it (PUT, PATCH or DELETE on objects account A read or made) as account B and with no login",
		"2 high, 1 medium",
		"3 accepted and may have changed data: PUT /api/items/8 as account B, DELETE /api/items/10 as account B, POST /orgs/3/settings as account B",
		"12 object(s) made for account A with POST /api/items/, POST /api/cards/, 11 of them deleted again by A",
		"1 not replayed because they could log in, log out or lock an account out: POST /logout",
		"1 write(s) were sent with the sender's own CSRF token, taken from a page",
		"not sent as account B because they make a new object that names no ID or login: POST /api/items/, POST /api/cards/, POST /api/notes",
	} {
		if !strings.Contains(s, part) {
			t.Errorf("summary %q\nlacks %q", s, part)
		}
	}
}

func TestWriteCheckWithoutCopies(t *testing.T) {
	srv, _ := writeApp(t)
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	// No recorded create: B's accepted DELETE hit A's recorded item (8,
	// made here), so the request with no login is not sent.
	if a, err := egress.SendHeader(context.Background(), cfg, "POST", "/api/items/", http.Header{"Authorization": {"Bearer A"}}, []byte(`{"Product":3}`), 1<<10); err != nil || a.Status != 201 {
		t.Fatal(a, err)
	}
	ws := []Write{{Method: "DELETE", Path: "/api/items/8", Header: http.Header{"Authorization": {"Bearer A"}}}}
	res, err := WriteCheck(context.Background(), cfg, ws, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "", 10, target.Local)
	if err != nil || len(res.Replays) != 2 || res.Replays[1].NotSent == "" || res.Replays[0].Recreated {
		t.Fatalf("%+v %v", res, err)
	}
	if fs := WriteFindings(srv.URL, res); len(fs) != 1 || fs[0].Severity != findings.High || !strings.Contains(fs[0].Message, "recorded object") {
		t.Errorf("%+v", fs)
	}
	if s := res.WriteSummary(nil); !strings.Contains(s, "not tested with no login, because B's replay was accepted on A's recorded object: DELETE /api/items/8") {
		t.Errorf("%q", s)
	}
	// With no login, the form gets the anonymous page's token and cookie;
	// the app redirects to its login page, which is a refusal.
	form := Write{Method: "POST", Path: "/orgs/3/settings", RecordedStatus: 303, CSRF: true,
		Header: http.Header{"Authorization": {"Bearer A"}, "Content-Type": {"application/x-www-form-urlencoded"}}, Body: []byte("_csrf=tok-alice-0123456789&name=A")}
	res, err = WriteCheck(context.Background(), cfg, []Write{form}, Accounts{}, "", 10, target.Local)
	if r := res.Replays[0]; err != nil || !r.CSRFSwapped || r.Answer.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, "/login") || r.Accepted() {
		t.Errorf("no-login form %+v %v", r, err)
	}
	// Without B, only the request with no login is sent.
	res, err = WriteCheck(context.Background(), cfg, []Write{{Method: "PUT", Path: "/api/cards/7", Header: http.Header{"Authorization": {"Bearer A"}}}}, Accounts{}, "", 10, target.Local)
	if err != nil || len(res.Replays) != 1 || res.Replays[0].Who != AsNoLogin || res.BTested {
		t.Fatalf("%+v %v", res, err)
	}
	if s := res.WriteSummary(nil); !strings.Contains(s, "accounts B and C are not tested") || !strings.Contains(s, "none was accepted") {
		t.Errorf("%q", s)
	}
}

func TestWriteCheckMedium(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		if r.Method == "GET" {
			fmt.Fprint(w, `{"same":true}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	ws := []Write{
		{Method: "POST", Path: "/repos/alice/pub/issues", Header: http.Header{"Authorization": {"Bearer A"}}, Body: []byte(`{"title":"x"}`)},
		{Method: "PUT", Path: "/user/starred/alice/pub", Header: http.Header{"Authorization": {"Bearer A"}}},
	}
	res, err := WriteCheck(context.Background(), cfg, ws, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
	if err != nil {
		t.Fatal(err)
	}
	fs := WriteFindings(srv.URL, res)
	// Accepted, but A's read did not change (PUT) or was not checked
	// (POST): medium, for a person to check. B's PUT was accepted on A's
	// recorded object, so the request with no login is not sent for it.
	if len(fs) != 3 || fs[0].RuleID != "cross-account-write" || fs[0].Severity != findings.Medium || fs[1].RuleID != "no-login-write" || fs[1].CWEs[0] != "CWE-306" || !strings.Contains(fs[0].Message, "check it by hand") {
		t.Errorf("%+v", fs)
	}
	if !slices.Equal(got[:3], []string{"POST /repos/alice/pub/issues", "POST /repos/alice/pub/issues", "GET /user/starred/alice/pub"}) {
		t.Errorf("sent %v", got)
	}
}

// TestWriteCheckNoActionGET: a write whose URL names an action is not read
// back with a GET (ADR 0048: such a GET may run the action), so it can reach
// medium only; the CSRF token comes from the start page, not a form page
// whose URL names an action.
func TestWriteCheckNoActionGET(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		if r.Method == "GET" {
			fmt.Fprint(w, `<meta name="_csrf" content="tok-`+r.Header.Get("Authorization")+`">`)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	ws := []Write{
		{Method: "PUT", Path: "/api/orders/7/approve", Header: http.Header{"Authorization": {"Bearer A"}}},
		{Method: "POST", Path: "/orders/7/edit", CSRF: true, Header: http.Header{"Authorization": {"Bearer A"}, "Referer": {srv.URL + "/orders/7/cancel"}, "Content-Type": {"application/x-www-form-urlencoded"}}, Body: []byte("_csrf=old&x=1")},
	}
	res, err := WriteCheck(context.Background(), cfg, ws, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "GET ") && g != "GET /" {
			t.Errorf("sent %s", g)
		}
	}
	for _, f := range WriteFindings(srv.URL, res) {
		if f.Severity != findings.Medium {
			t.Errorf("%+v", f)
		}
	}
	if !slices.Contains(got, "GET /") {
		t.Errorf("no token page: %v", got)
	}
}

func TestWriteCheckRefuses(t *testing.T) {
	tu := mustTarget(t, "http://127.0.0.1:1/")
	ws := []Write{{Method: "DELETE", Path: "/x"}}
	if _, err := WriteCheck(context.Background(), egress.Config{Target: tu}, ws, Accounts{}, "", 1, target.Deployed); err == nil || !strings.Contains(err.Error(), "local targets") {
		t.Errorf("deployed: %v", err)
	}
	if _, err := WriteCheck(context.Background(), egress.Config{Target: tu, ReadOnly: true}, ws, Accounts{}, "", 1, target.Local); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("read-only: %v", err)
	}
}

func FuzzParseWrites(f *testing.F) {
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"POST","url":"http://localhost:3000/a/","postData":{"mimeType":"application/json","text":"{}"}},"response":{"status":201,"content":{"text":"{\"data\":{\"id\":7}}"}}},{"request":{"method":"PUT","url":"http://localhost:3000/a/7"}}]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"DELETE","url":"http://localhost:3000/user/1"}}]}}`))
	tu, err := target.Parse("http://localhost:3000/")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		w, err := ParseWrites(data, tu)
		if err != nil {
			return
		}
		if len(w.Writes) > MaxWrites {
			t.Fatalf("%d writes", len(w.Writes))
		}
		for _, x := range w.Writes {
			if !writeMethods[x.Method] || !target.SendablePath(x.Path) || lockoutReason(x.Method, x.Path) != "" || x.Header.Get("Host") != "" {
				t.Fatalf("%+v", x)
			}
			if x.Create != nil {
				_ = x.withID(x.Create.OldID, "1")
			}
		}
	})
}

func TestGraphQLOp(t *testing.T) {
	for _, c := range []struct {
		body, kind, name string
		ok               bool
	}{
		{`{"query":"mutation EditPaste($id: Int!) { editPaste(id: $id) { paste { id } } }","variables":{"id":1}}`, "mutation", "EditPaste", true},
		// An unnamed mutation is named by its field; a namespace field
		// with no arguments adds the field inside it (Wiki.js 2).
		{`{"query":"mutation { deletePaste(id: 1) { result } }"}`, "mutation", "deletePaste", true},
		{`[{"operationName":null,"query":"mutation ($id: Int!) {\n  pages {\n    update(id: $id) {\n      responseResult { succeeded }\n    }\n  }\n}"}]`, "mutation", "pages.update", true},
		{`{"query":"mutation { x: deletePaste(id: 1) { result } }"}`, "mutation", "deletePaste", true},
		{`{"query":"mutation { }"}`, "mutation", "mutation", true},
		{`{"query":"query getPastes { pastes { id } }"}`, "query", "", true},
		{`{"query":"{ pastes { id } }"}`, "query", "", true},
		{`{"query":"subscription s { paste { id } }"}`, "subscription", "", true},
		// operationName picks the operation that runs.
		{`{"query":"query A { a } mutation B { b }","operationName":"B"}`, "mutation", "B", true},
		{`{"query":"query A { a } mutation B { b }","operationName":"A"}`, "query", "", true},
		// A comment naming a mutation is not one.
		{`{"query":"# mutation X\nquery Y { y }"}`, "query", "", true},
		{`[{"query":"query a { a }"},{"query":"mutation m { m }"}]`, "mutation", "m", true},
		{`[{"query":"query a { a }"},{"query":"{ b }"}]`, "query", "", true},
		// A persisted query sent by its hash, plain JSON, a form: not recognised.
		{`{"extensions":{"persistedQuery":{"sha256Hash":"abc"}}}`, "", "", false},
		{`{"title":"x"}`, "", "", false},
		{`query=x`, "", "", false},
		{`[]`, "", "", false},
	} {
		kind, name, _, ok := graphQLOp([]byte(c.body))
		if kind != c.kind || name != c.name || ok != c.ok {
			t.Errorf("%s: %q %q %v", c.body, kind, name, ok)
		}
	}
	if _, _, f, _ := graphQLOp([]byte(`{"query":"mutation ($u: String!) { authentication { login(username: $u) { jwt } } }"}`)); strings.Join(f, ".") != "authentication.login" {
		t.Errorf("fields %q", f)
	}
}

func TestGraphQLRefused(t *testing.T) {
	for body, want := range map[string]bool{
		`{"errors":[{"message":"not allowed"}],"data":{"editPaste":null}}`: true,
		`{"errors":[{"message":"not allowed"}],"data":null}`:               true,
		`{"errors":[{"message":"not allowed"}]}`:                           true,
		`{"errors":[{"message":"partly"}],"data":{"editPaste":{"id":1}}}`:  false,
		`{"data":{"editPaste":{"id":1}}}`:                                  false,
		`[{"errors":[{"message":"x"}]},{"errors":[{"message":"y"}]}]`:      true,
		`[{"errors":[{"message":"x"}]},{"data":{"m":1}}]`:                  false,
		`not json`: false,
		// Refused in the payload (Wiki.js 2), and a batch whose data
		// holds only nulls and __typename.
		`[{"data":{"pages":{"update":{"responseResult":{"succeeded":false,"message":"Forbidden"},"__typename":"PageResponse"}}}}]`: true,
		`[{"data":{"pages":{"update":{"responseResult":{"succeeded":true}}}}}]`:                                                    false,
		`[{"errors":[{"message":"Forbidden"}],"data":{"pages":{"create":null,"__typename":"PageMutation"}}}]`:                      true,
		`{"data":{"productUpdate":{"userErrors":[{"message":"no"}],"product":null}}}`:                                              true,
		`{"data":{"productUpdate":{"userErrors":[],"product":{"id":1}}}}`:                                                          false,
	} {
		if got := graphQLRefused([]byte(body)); got != want {
			t.Errorf("%s: %v", body, got)
		}
	}
}

// TestWriteCheckGraphQL: queries are reads and are not replayed; a
// mutation refused with 200 and an "errors" list is not accepted; one the
// app lets B run on A's copy is.
func TestWriteCheckGraphQL(t *testing.T) {
	for _, ownerCheck := range []bool{true, false} {
		var mu sync.Mutex
		notes, next := map[int]string{}, 7
		var sent []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			u := map[string]string{"Bearer A": "alice", "Bearer B": "bob"}[r.Header.Get("Authorization")]
			var q struct {
				Query     string         `json:"query"`
				Variables map[string]any `json:"variables"`
			}
			json.NewDecoder(r.Body).Decode(&q)
			sent = append(sent, u+" "+strings.Fields(q.Query)[0]+" "+strings.Fields(q.Query)[1])
			refuse := func() { fmt.Fprint(w, `{"errors":[{"message":"not allowed"}],"data":{"x":null}}`) }
			switch {
			case u == "":
				refuse()
			case strings.HasPrefix(q.Query, "mutation createNote"):
				next++
				notes[next] = u
				fmt.Fprintf(w, `{"data":{"createNote":{"note":{"id":%d}}}}`, next)
			case strings.HasPrefix(q.Query, "mutation editNote"):
				id := int(q.Variables["id"].(float64))
				if notes[id] == "" || ownerCheck && notes[id] != u {
					refuse()
					return
				}
				fmt.Fprint(w, `{"data":{"editNote":{"ok":true}}}`)
			default:
				fmt.Fprint(w, `{"data":{"notes":[]}}`)
			}
		}))
		noSleep(t)
		a := map[string]string{"Authorization": "Bearer A"}
		u := srv.URL + "/graphql"
		har := writeHAR(t, []writeEntry{
			{method: "POST", url: u, headers: a, mime: "application/json", body: `{"query":"query notes { notes { id } }"}`, status: 200, answer: `{"data":{"notes":[]}}`},
			{method: "POST", url: u, headers: a, mime: "application/json", body: `{"query":"mutation createNote { createNote(text: \"x\") { note { id } } }"}`, status: 200, answer: `{"data":{"createNote":{"note":{"id":7}}}}`},
			{method: "POST", url: u, headers: a, mime: "application/json", body: `{"query":"mutation editNote($id: Int!) { editNote(id: $id) { ok } }","variables":{"id":7}}`, status: 200, answer: `{"data":{"editNote":{"ok":true}}}`},
		})
		tu := mustTarget(t, srv.URL+"/")
		ws, err := ParseWrites(har, tu)
		if err != nil || len(ws.Writes) != 2 || ws.GraphQLReads != 1 || ws.Writes[1].GraphQL != "editNote" || ws.Writes[1].Create == nil ||
			ws.Writes[1].Label() != "POST /graphql (GraphQL editNote)" {
			t.Fatalf("%v %+v", err, ws)
		}
		cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
		res, err := WriteCheck(context.Background(), cfg, ws.Writes, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		fs := WriteFindings(srv.URL, res)
		for _, s := range sent {
			if strings.HasPrefix(s, " query") || strings.HasPrefix(s, "bob query") {
				t.Errorf("a query was replayed: %v", sent)
			}
		}
		if ownerCheck && len(fs) != 0 {
			t.Errorf("owner-checked: %+v", fs)
		}
		if !ownerCheck && (len(fs) != 1 || fs[0].RuleID != "cross-account-write" || fs[0].Severity != findings.Medium ||
			!strings.Contains(fs[0].Message, "POST /graphql (GraphQL editNote)")) {
			t.Errorf("not owner-checked: %+v", fs)
		}
		if sum := res.WriteSummary(ws); !strings.Contains(sum, "1 GraphQL queries or subscriptions (reads) not replayed") {
			t.Errorf("summary %s", sum)
		}
	}
}

// TestWriteCheckTriesAndSteps: a DELETE the recording never made is tried
// on a copy of A's note and found; A's basket items are sent again before
// B's checkout, and A's read of the basket shows the change (high), unless
// that read differs on its own (medium).
func TestWriteCheckTriesAndSteps(t *testing.T) {
	for _, noisy := range []bool{false, true} {
		var mu sync.Mutex
		notes, basket, next, reads := map[int]string{}, []int{}, 7, 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			u := map[string]string{"Bearer A": "alice", "Bearer B": "bob"}[r.Header.Get("Authorization")]
			if u == "" {
				http.Error(w, "log in", http.StatusUnauthorized)
				return
			}
			var id int
			switch {
			case r.Method == "POST" && r.URL.Path == "/api/notes/":
				next++
				notes[next] = u
				fmt.Fprintf(w, `{"data":{"id":%d}}`, next)
			case r.Method == "GET" && sscan(r.URL.Path, "/api/notes/%d", &id):
				if notes[id] != u {
					http.NotFound(w, r)
					return
				}
				fmt.Fprintf(w, `{"data":{"id":%d,"text":"x"}}`, id)
			case r.Method == "DELETE" && sscan(r.URL.Path, "/api/notes/%d", &id): // no owner check
				if notes[id] == "" {
					http.NotFound(w, r)
					return
				}
				delete(notes, id)
			case r.Method == "PUT" || r.Method == "PATCH":
				http.Error(w, "no", http.StatusMethodNotAllowed)
			case r.Method == "POST" && r.URL.Path == "/api/basketitems/":
				if u != "alice" { // basket 5 is alice's
					http.Error(w, "not your basket", http.StatusForbidden)
					return
				}
				basket = append(basket, 1)
				fmt.Fprint(w, `{"ok":true}`)
			case r.Method == "GET" && r.URL.Path == "/rest/basket/5":
				reads++
				if noisy {
					fmt.Fprintf(w, `{"items":%d,"at":%d}`, len(basket), reads)
					return
				}
				fmt.Fprintf(w, `{"items":%d}`, len(basket))
			case r.Method == "POST" && r.URL.Path == "/rest/basket/5/checkout": // no owner check
				basket = nil
				fmt.Fprint(w, `{"ok":true}`)
			default:
				http.NotFound(w, r)
			}
		}))
		noSleep(t)
		a := map[string]string{"Authorization": "Bearer A"}
		u := srv.URL
		har := writeHAR(t, []writeEntry{
			{method: "POST", url: u + "/api/notes/", headers: a, mime: "application/json", body: `{"text":"x"}`, status: 201, answer: `{"data":{"id":7}}`},
			{method: "GET", url: u + "/api/notes/7", headers: a, status: 200, answer: `{"data":{"id":7,"text":"x"}}`},
			{method: "POST", url: u + "/api/basketitems/", headers: a, mime: "application/json", body: `{"ProductId":1,"BasketId":"5"}`, status: 200, answer: `{"ok":true}`},
			{method: "GET", url: u + "/rest/basket/5", headers: a, status: 200, answer: `{"items":1}`},
			{method: "POST", url: u + "/rest/basket/5/checkout", headers: a, mime: "application/json", body: `{"pay":"card"}`, status: 200, answer: `{"ok":true}`},
		})
		tu := mustTarget(t, u+"/")
		ws, err := ParseWrites(har, tu)
		if err != nil {
			t.Fatal(err)
		}
		var labels []string
		for _, x := range ws.Writes {
			labels = append(labels, fmt.Sprintf("%s %v %d %s", x.Label(), x.Tried, len(x.Steps), x.Parent))
		}
		want := []string{"POST /api/notes/ false 0 ", "POST /api/basketitems/ false 0 ", "POST /rest/basket/5/checkout false 1 /rest/basket/5", "PUT /api/notes/7 true 0 ", "PATCH /api/notes/7 true 0 ", "PUT /rest/basket/5 true 0 ", "PATCH /rest/basket/5 true 0 ", "DELETE /api/notes/7 true 0 ", "DELETE /rest/basket/5 true 0 "}
		if !slices.Equal(labels, want) {
			t.Fatalf("writes %q\nwant %q", labels, want)
		}
		cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
		res, err := WriteCheck(context.Background(), cfg, ws.Writes, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range WriteFindings(u, res) {
			got = append(got, fmt.Sprintf("%s %s %v", f.RuleID, strings.TrimPrefix(f.Location.URI, u), f.Severity))
		}
		checkout := "cross-account-write /rest/basket/5/checkout high"
		if noisy {
			checkout = "cross-account-write /rest/basket/5/checkout medium"
		}
		wantF := []string{checkout, "cross-account-write /api/notes/7 high"}
		if !slices.Equal(got, wantF) {
			t.Errorf("noisy %v: findings %q, want %q", noisy, got, wantF)
		}
		// Sent once, before B's checkout: B's was accepted on A's recorded
		// basket, so the checkout is not sent with no login.
		if res.StepsSent != 1 || !strings.Contains(res.WriteSummary(ws), "1 of account A's earlier recorded writes sent again first") {
			t.Errorf("steps %d: %s", res.StepsSent, res.WriteSummary(ws))
		}
	}
}

func sscan(s, format string, id *int) bool {
	n, err := fmt.Sscanf(s, format, id)
	return err == nil && n == 1
}

// TestParseWritesGraphQLBatch: Wiki.js 2 sends each operation as a batch
// of one with no operation name (recorded 2026-11-21). The login mutation
// is never replayed, and a page update finds the create that made its
// page through the ID five levels down in the batch's one answer.
func TestParseWritesGraphQLBatch(t *testing.T) {
	a := map[string]string{"Authorization": "Bearer A"}
	u := "http://127.0.0.1:3002/graphql"
	har := writeHAR(t, []writeEntry{
		{method: "POST", url: u, headers: a, mime: "application/json", status: 200,
			body:   `[{"operationName":null,"variables":{"username":"a","password":"p"},"query":"mutation ($username: String!, $password: String!) {\n  authentication {\n    login(username: $username, password: $password) {\n      jwt\n    }\n  }\n}"}]`,
			answer: `[{"data":{"authentication":{"login":{"responseResult":{"succeeded":true},"jwt":"x"}}}}]`},
		{method: "POST", url: u, headers: a, mime: "application/json", status: 200,
			body:   `[{"operationName":null,"variables":{"path":"alice/notes","content":"x"},"query":"mutation ($path: String!, $content: String!) {\n  pages {\n    create(path: $path, content: $content) {\n      page { id }\n    }\n  }\n}"}]`,
			answer: `[{"data":{"pages":{"create":{"responseResult":{"succeeded":true},"page":{"id":1,"__typename":"Page"}}}}}]`},
		{method: "POST", url: u, headers: a, mime: "application/json", status: 200,
			body:   `[{"operationName":null,"variables":{"id":1,"content":"y"},"query":"mutation ($id: Int!, $content: String!) {\n  pages {\n    update(id: $id, content: $content) {\n      responseResult { succeeded }\n    }\n  }\n}"}]`,
			answer: `[{"data":{"pages":{"update":{"responseResult":{"succeeded":true}}}}}]`},
	})
	ws, err := ParseWrites(har, mustTarget(t, "http://127.0.0.1:3002/"))
	if err != nil || ws.Lockout != 1 || len(ws.LockoutPaths) != 1 || ws.LockoutPaths[0] != "POST /graphql (GraphQL authentication.login)" {
		t.Fatalf("%v %+v", err, ws)
	}
	var upd *Write
	for i := range ws.Writes {
		if ws.Writes[i].GraphQL == "pages.update" {
			upd = &ws.Writes[i]
		}
	}
	if upd == nil || upd.Create == nil || strings.Join(upd.Create.Field, ".") != "data.pages.create.page.id" || upd.Create.OldID != "1" {
		t.Fatalf("%+v", ws.Writes)
	}
	if id, ok := newID(Answer{Status: 200, Body: []byte(`[{"data":{"pages":{"create":{"page":{"id":9}}}}}]`)}, upd.Create.Field, false); !ok || id != "9" {
		t.Errorf("newID %q %v", id, ok)
	}
}
