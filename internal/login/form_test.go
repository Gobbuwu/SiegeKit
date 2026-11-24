package login

import (
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
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
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// Pages as Next.js 16.4.6 rendered them on the test bed (2026-11-23): the
// Supabase guide's <button formAction={login}>, and useActionState.
const (
	nextButtonPage = `<!DOCTYPE html><html><head><script src="/_next/static/chunks/a.js" async=""></script></head><body><form><label for="email">Email:</label><input id="email" type="email" required="" name="email"/><label for="password">Password:</label><input id="password" type="password" required="" name="password"/><button name="$ACTION_ID_40a447eae830bdd756be2f26c2d16a70f7462e7730" formAction="" formEncType="multipart/form-data" formMethod="POST">Log in</button></form><script>self.__next_f.push([1,"<form action=/evil method=post><input name=email><input name=password>"])</script></body></html>`
	nextStatePage  = `<form action="" encType="multipart/form-data" method="POST"><input type="hidden" name="$ACTION_REF_1"/><input type="hidden" name="$ACTION_1:0" value="{&quot;id&quot;:&quot;60df375f7767b6d2657ac67c5bf0468db77c036ad2&quot;,&quot;bound&quot;:&quot;$@1&quot;}"/><input type="hidden" name="$ACTION_1:1" value="[null]"/><input type="hidden" name="$ACTION_KEY" value="k1d9d0146a2efa55bcf671ea1b28919fd"/><input type="email" required="" name="email"/><input type="password" required="" name="password"/><button>Log in</button></form>`
)

var tmpl = []field{{"email", "{user}"}, {"password", "{password}"}}

func buildPage(t *testing.T, html, pageURL string) (*formLogin, error) {
	t.Helper()
	tu := mustTarget(t, "http://127.0.0.1:3100/")
	pu, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	return readPage([]byte(html)).build(pu, tu, tmpl, "a@b.test", "pw&x=1")
}

// entries decodes a built body into name=value pairs, in order.
func entries(t *testing.T, fl *formLogin) []string {
	t.Helper()
	var out []string
	mt, params, _ := mime.ParseMediaType(fl.contentType)
	switch mt {
	case "multipart/form-data":
		r := multipart.NewReader(strings.NewReader(string(fl.body)), params["boundary"])
		for {
			p, err := r.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(p)
			out = append(out, p.FormName()+"="+string(b))
		}
	case "application/x-www-form-urlencoded":
		for kv := range strings.SplitSeq(string(fl.body), "&") {
			k, v, _ := strings.Cut(kv, "=")
			k, _ = url.QueryUnescape(k)
			v, _ = url.QueryUnescape(v)
			out = append(out, k+"="+v)
		}
	default:
		t.Fatalf("content type %q", fl.contentType)
	}
	return out
}

func TestFormNextJS(t *testing.T) {
	fl, err := buildPage(t, nextButtonPage, "http://127.0.0.1:3100/login")
	if err != nil {
		t.Fatal(err)
	}
	// The button's formaction (empty: the page), formmethod and
	// formenctype win; its name is sent; the form inside the script is
	// not a form.
	want := []string{"email=a@b.test", "password=pw&x=1", "$ACTION_ID_40a447eae830bdd756be2f26c2d16a70f7462e7730="}
	if got := entries(t, fl); !slices.Equal(got, want) || fl.path != "/login" || fl.button != "Log in" || fl.describe() != `multipart/form-data, button "Log in"` {
		t.Errorf("%v %+v", got, fl)
	}
	fl, err = buildPage(t, nextStatePage, "http://127.0.0.1:3100/login2")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"$ACTION_REF_1=", `$ACTION_1:0={"id":"60df375f7767b6d2657ac67c5bf0468db77c036ad2","bound":"$@1"}`, "$ACTION_1:1=[null]", "$ACTION_KEY=k1d9d0146a2efa55bcf671ea1b28919fd", "email=a@b.test", "password=pw&x=1"} // gitleaks:allow (the action key of a page Next.js rendered for the test, not a secret)
	if got := entries(t, fl); !slices.Equal(got, want) || fl.path != "/login2" {
		t.Errorf("%v %+v", got, fl)
	}
}

func TestFormRules(t *testing.T) {
	for _, c := range []struct {
		name, html, page string
		want             []string
		path             string
	}{
		{"csrf hidden field, urlencoded, relative action",
			`<form method="post" action="login/?next=%2F"><input type="hidden" name="csrfmiddlewaretoken" value="tok&amp;1"><input name="email"><input type="password" name="password"><input type="submit" value="Sign in"></form>`,
			"http://127.0.0.1:3100/accounts/", []string{"csrfmiddlewaretoken=tok&1", "email=a@b.test", "password=pw&x=1"}, "/accounts/login/?next=%2F"},
		{"base href and a named submit input",
			`<head><base href="/app/"></head><form method=POST action=session><input name=email value=old><input name=password type=password><input type=submit name=commit value="Log in"></form>`,
			"http://127.0.0.1:3100/x/y", []string{"email=a@b.test", "password=pw&x=1", "commit=Log in"}, "/app/session"},
		{"disabled, unchecked, checked, select, textarea, file, reset, other buttons",
			`<form method=post><input name=d disabled value=1><input type=checkbox name=c1><input type=checkbox name=c2 checked><input type=radio name=r value=v checked>` +
				`<select name=s><option value=a>A<option selected value=b>B</select><select name=s2><option disabled>x<option>first one</select><select name=m multiple><option>p</select>` +
				`<textarea name=t>` + "\n" + `a &lt;b&gt;</textarea><input type=file name=f><input type=reset name=rs><button type=button name=bb>x</button>` +
				`<input name=email><input type=password name=password><button name=go value=1>Go</button><button name=other>No</button></form>`,
			"http://127.0.0.1:3100/", []string{"c2=on", "r=v", "s=b", "s2=first one", "t=a <b>", "email=a@b.test", "password=pw&x=1", "go=1"}, "/"},
		{"form attribute; a nested form start ignored, its end ends the outer one",
			`<form id=f method=post action=/in><input name=email><form action=/nested><input name=x></form><input name=after><input form=f type=password name=password><input form=nowhere name=x><button form=f>Log in</button>`,
			"http://127.0.0.1:3100/", []string{"email=a@b.test", "x=", "password=pw&x=1"}, "/in"},
		{"image submit button, comments skipped",
			`<!-- <form action=/old method=post><input name=email><input name=password></form> --><form method=post action=/new><input name=email><input name=password type=password><input type=image name=go src=b.png></form>`,
			"http://127.0.0.1:3100/", []string{"email=a@b.test", "password=pw&x=1", "go.x=0", "go.y=0"}, "/new"},
		{"the first form with the fields",
			`<form method=post action=/search><input name=q></form><form method=post action=/signin><input name=email><input name=password type=password></form><form method=post action=/signup><input name=email><input name=password type=password></form>`,
			"http://127.0.0.1:3100/", []string{"email=a@b.test", "password=pw&x=1"}, "/signin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fl, err := buildPage(t, c.html, c.page)
			if err != nil {
				t.Fatal(err)
			}
			if got := entries(t, fl); !slices.Equal(got, c.want) || fl.path != c.path {
				t.Errorf("got %v %s, want %v %s", got, fl.path, c.want, c.path)
			}
		})
	}
}

func TestFormRefused(t *testing.T) {
	for _, c := range []struct{ html, want string }{
		{`<p>no form</p>`, "has no <form>"},
		{`<form method=post><input name=user><input name=password></form>`, `no form with the fields "email" and "password" (form 1 has user, password)`},
		{`<form><input name=email><input name=password type=password><button>Go</button></form>`, "sent with GET"},
		{`<form method=dialog><input name=email><input name=password></form>`, "sent with DIALOG"},
		{`<form method=post enctype=text/plain><input name=email><input name=password></form>`, "text/plain"},
		{`<form method=post action="javascript:throw new Error('x')"><input name=email><input name=password></form>`, "only by JavaScript"},
		{`<form method=post action="http://evil.test/login"><input name=email><input name=password></form>`, "not on the target's origin"},
		{`<form method=post action="//evil.test/login"><input name=email><input name=password></form>`, "not on the target's origin"},
		{`<form method=post action="https://127.0.0.1:3100/login"><input name=email><input name=password></form>`, "not on the target's origin"},
		{`<form method=post><input name=email><input name=password><button disabled>Go</button></form>`, "is disabled"},
		{`<form method=post><input name=email><input name=password type=password disabled></form>`, ""},
	} {
		_, err := buildPage(t, c.html, "http://127.0.0.1:3100/login")
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.html, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.html, err, c.want)
		}
	}
}

func TestCookies(t *testing.T) {
	h := http.Header{"Set-Cookie": {
		"csrftoken=abc; Path=/; SameSite=Lax",
		"old=1; Max-Age=0",
		"gone=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		"other=1; Domain=evil.test",
		"api=1; Path=/api",
		"dir=1", // default path: the page's directory, /accounts
		"sub=1; Domain=example.test",
		"csrftoken=def; Path=/",
	}}
	n := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	if got := cookies(h, "127.0.0.1", "/accounts/login", "/accounts/login", n); got != "csrftoken=def; dir=1" {
		t.Error(got)
	}
	if got := cookies(h, "app.example.test", "/login", "/api/x", n); got != "csrftoken=def; api=1; dir=1; sub=1" { // the default path of /login is /
		t.Error(got)
	}
	if got := cookies(h, "127.0.0.1", "/login", "/apix", n); got != "csrftoken=def; dir=1" {
		t.Error(got)
	}
}

func TestRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"":                                    "",
		"/error?code=invalid_credentials":     "/error?code=invalid_credentials",
		"/error?code=over_request_rate_limit": "/error?code=over_request_rate_limit",
		"/login;jsessionid=A1B2C3D4E5F6?t=1732400000123":     "/login;jsessionid=*?t=*",
		"/x/550e8400-e29b-41d4-a716-446655440000#s=ab12cd34": "/x/*#s=*",
		"http://127.0.0.1:3100/login?attempt=3":              "http://127.0.0.1:3100/login?attempt=3",
	} {
		if got := redirect(&egress.Answer{Header: http.Header{"Location": {in}}}); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestParsePage(t *testing.T) {
	tu := mustTarget(t, "http://127.0.0.1:3100/")
	l, err := ParsePage("http://127.0.0.1:3100/login?next=%2F", "a@b.test", "email={user}&password={password}&remember=on", tu)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Page || l.URL != "http://127.0.0.1:3100/login?next=%2F" || l.Path != "/login?next=%2F" || len(l.fields) != 3 || l.fields[2] != (field{"remember", "on"}) {
		t.Errorf("%+v", l)
	}
	for _, c := range []struct{ page, body, want string }{
		{"http://127.0.0.1:3101/login", "e={user}&p={password}", "not on the target's origin"},
		{"http://127.0.0.1:3100/login#x", "e={user}&p={password}", "fragment"},
		{"http://127.0.0.1:3100/login", `{"e":"{user}","p":"{password}"}`, "as a form body"},
		{"http://127.0.0.1:3100/login", "e={user}&p={password}&e=x", "twice"},
		{"http://127.0.0.1:3100/login", "e={user}&{password}=x", "in a field name"},
		{"http://127.0.0.1:3100/login", "e={user}&=x&p={password}", "no name"},
		{"http://127.0.0.1:3100/login", "e={user}&p=%zz{password}", "not a valid form body"},
		{"http://127.0.0.1:3100/login", "e={user}", "must contain"},
	} {
		if _, err := ParsePage(c.page, "u", c.body, tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, want %q", c.page, c.body, err, c.want)
		}
	}
	for _, p := range []string{"", strings.Repeat("x", maxPassword+1), "a\nb", "\xff"} {
		if CheckPassword(p) == nil {
			t.Errorf("password %q accepted", p)
		}
	}
	if CheckPassword("correct horse ü") != nil {
		t.Error("a password refused")
	}
}

// formApp is a login page like a Next.js Server Action form: the page has
// a form with a hidden action field and a cookie, sent as multipart; any
// other POST gets the page back, unprocessed (measured on Next.js 16). A
// right login redirects to /, a wrong one to /error, and after limit wrong
// logins to /error?code=over_request_rate_limit.
type formApp struct {
	mu      sync.Mutex
	wrong   int
	limit   int
	served  int
	posts   []*http.Request
	page    string
	pageErr func(n int) (int, string) // replaces the page's answer after n reads
}

func (a *formApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}
	page := a.page
	if page == "" {
		page = `<form><input name=email type=email><input name=password type=password><button name="$ACTION_ID_abc123" formAction="" formEncType="multipart/form-data" formMethod="POST">Log in</button></form>`
	}
	if r.Method == http.MethodGet {
		a.served++
		if a.pageErr != nil {
			if s, b := a.pageErr(a.served); s != 0 {
				w.WriteHeader(s)
				io.WriteString(w, b)
				return
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: fmt.Sprint(a.served), Path: "/"})
		io.WriteString(w, page)
		return
	}
	a.posts = append(a.posts, r)
	if err := r.ParseMultipartForm(1 << 20); err != nil || r.MultipartForm.Value["$ACTION_ID_abc123"] == nil {
		io.WriteString(w, page) // not run: the page again
		return
	}
	if c, err := r.Cookie("csrf"); err != nil || c.Value != fmt.Sprint(a.served) || r.Header.Get("Origin") != "http://"+r.Host {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	switch {
	case r.FormValue("password") == right:
		http.SetCookie(w, &http.Cookie{Name: "sb-auth-token", Value: "x"})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case a.limit > 0 && a.wrong >= a.limit:
		http.Redirect(w, r, "/error?code=over_request_rate_limit", http.StatusSeeOther)
	default:
		a.wrong++
		http.Redirect(w, r, "/error?code=invalid_credentials", http.StatusSeeOther)
	}
}

func serveForm(t *testing.T, a *formApp) (*target.URL, egress.Config) {
	t.Helper()
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	tu := mustTarget(t, srv.URL+"/")
	old := sleep
	t.Cleanup(func() { sleep = old })
	sleep = func(context.Context, time.Duration) error { return nil }
	return tu, egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
}

// The false finding of the Porchlet run (2026-11-23): an urlencoded post
// to a Server Action page gets the page back and never runs. The right
// password is answered the same, so the check now fails with the reason.
func TestFormIgnoredLoginFails(t *testing.T) {
	a := &formApp{}
	tu, cfg := serveForm(t, a)
	l, err := Parse(tu.Origin()+"/login", "tester@shop.test", "email={user}&password={password}", tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), cfg, l, 5, right)
	if err == nil || !strings.Contains(err.Error(), "were both answered 200") || !strings.Contains(err.Error(), "needs --login-page") || strings.Contains(err.Error(), right) {
		t.Fatalf("%+v %v", r, err)
	}
	if len(a.posts) != 2 || Findings(l, r, 5) != nil {
		t.Errorf("%d posts", len(a.posts))
	}
}

func TestFormLogin(t *testing.T) {
	a := &formApp{}
	tu, cfg := serveForm(t, a)
	l, err := ParsePage(tu.Origin()+"/login", "tester@shop.test", "email={user}&password={password}", tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), cfg, l, 5, right)
	if err != nil || r.Limited || r.Attempts != 5 || r.Requests != 17 || r.Baseline != 303 || r.Redirect != "/error?code=invalid_credentials" ||
		r.Right != "answered 303 to / setting the cookies sb-auth-token" || r.Form != `multipart/form-data, button "Log in"` || r.URL != tu.Origin()+"/login" {
		t.Fatalf("%+v %v", r, err)
	}
	if a.served != 6 || len(a.posts) != 6 || a.wrong != 5 {
		t.Errorf("%d pages, %d posts, %d wrong", a.served, len(a.posts), a.wrong)
	}
	// 5 attempts are too few for a finding (issue #79); the message of 20
	// such answers names the form's answers.
	if fs := Findings(l, r, 5); fs != nil {
		t.Errorf("%+v", fs)
	}
	r20 := r
	r20.Attempts = DefaultAttempts
	fs := Findings(l, r20, DefaultAttempts)
	if len(fs) != 1 || fs[0].Location.URI != tu.Origin()+"/login" || !strings.Contains(fs[0].Message, "same answer (303 to /error?code=invalid_credentials)") ||
		!strings.Contains(fs[0].Message, "right password first answered 303 to /") {
		t.Errorf("%+v", fs)
	}
	if s := r.Summary(5); s != "no limit seen in 5 attempts, all answered 303 to /error?code=invalid_credentials; the right password answered 303 to / setting the cookies sb-auth-token; too few attempts to report a finding, since many apps limit failed logins at 5 to 30: run again with --login-attempts 20 or more" {
		t.Error(s)
	}
	// Supabase's limit shows only in the redirect.
	a = &formApp{limit: 3}
	tu, cfg = serveForm(t, a)
	l, _ = ParsePage(tu.Origin()+"/login", "tester@shop.test", "email={user}&password={password}", tu)
	r, err = Check(context.Background(), cfg, l, 10, right)
	if err != nil || !r.Limited || r.Attempts != 4 || r.Signal != "redirected to /error?code=over_request_rate_limit instead of /error?code=invalid_credentials" {
		t.Fatalf("%+v %v", r, err)
	}
	// A limit for the whole address still holds when spraying starts: its
	// first answer is the limited one, and that is a limit, not a normal
	// answer that later changes (measured with Supabase Auth, 2026-11-23).
	sr, err := Spray(context.Background(), cfg, l, 10, r)
	if err != nil || !sr.Limited || sr.Attempts != 1 || !strings.Contains(sr.Signal, "the answer that showed login-throttle's limit (answered 303 to /error?code=over_request_rate_limit)") || len(SprayFindings(l, sr, 10)) != 0 {
		t.Fatalf("%+v %v", sr, err)
	}
	// Spraying sends the form too, for invented names, with no right login.
	a = &formApp{}
	tu, cfg = serveForm(t, a)
	l, _ = ParsePage(tu.Origin()+"/login", "tester@shop.test", "email={user}&password={password}", tu)
	r, err = Spray(context.Background(), cfg, l, 3, Result{})
	if err != nil || r.Limited || r.Attempts != 3 || r.Right != "" || a.posts[2].FormValue("email") != "siegekit-nobody-3@example.com" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFormPageChanges(t *testing.T) {
	for _, c := range []struct {
		name    string
		pageErr func(n int) (int, string)
		page    string
		want    string // the signal, or the error
		limited bool
	}{
		{"page 429", func(n int) (int, string) {
			if n > 3 {
				return 429, ""
			}
			return 0, ""
		}, "", "the login page answered 429", true},
		{"page 403", func(n int) (int, string) {
			if n > 3 {
				return 403, "blocked"
			}
			return 0, ""
		}, "", "the login page answered 403 instead of 200", true},
		{"page 500", func(n int) (int, string) {
			if n > 3 {
				return 500, ""
			}
			return 0, ""
		}, "", "the login page answered 500 (a server error) after 3 login(s)", false},
		{"captcha appears", func(n int) (int, string) {
			if n > 3 {
				return 200, `<p>Please solve the CAPTCHA</p><form><input name=email><input name=password type=password><button name="$ACTION_ID_abc123" formAction="" formEncType="multipart/form-data" formMethod="POST">Log in</button></form>`
			}
			return 0, ""
		}, "", `the login page says "captcha"`, true},
		{"form gone", func(n int) (int, string) {
			if n > 3 {
				return 200, "<p>Maintenance</p>"
			}
			return 0, ""
		}, "", "after 3 login(s) the login page's form could not be sent", false},
		{"first page redirects", func(int) (int, string) { return 302, "" }, "", "the login page answered 302", false},
		{"no form", nil, "<p>JavaScript needed</p>", "has no <form>", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := &formApp{pageErr: c.pageErr, page: c.page}
			tu, cfg := serveForm(t, a)
			l, _ := ParsePage(tu.Origin()+"/login", "tester", "email={user}&password={password}", tu)
			r, err := Check(context.Background(), cfg, l, 10, right)
			if c.limited {
				if err != nil || !r.Limited || !strings.Contains(r.Signal, c.want) {
					t.Errorf("%+v %v", r, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%+v %v, want %q", r, err, c.want)
			}
		})
	}
}

// FuzzReadPage checks that any page is read without a panic, and that a
// built form is on the target's origin.
func FuzzReadPage(f *testing.F) {
	for _, s := range []string{nextButtonPage, nextStatePage, "<form", "<form method=post><input name=email><input name=password><select name=s><option", "<textarea name=email>", "<!--", "</form", "<base href=//evil.test/><form method=post action=x><input name=email><input name=password>"} {
		f.Add(s)
	}
	tu, _ := target.Parse("http://127.0.0.1:3100/")
	pu, _ := url.Parse("http://127.0.0.1:3100/login")
	f.Fuzz(func(t *testing.T, s string) {
		fl, err := readPage([]byte(s)).build(pu, tu, tmpl, "u", "p")
		if err != nil {
			return
		}
		if !target.SendablePath(fl.path) || !strings.HasPrefix(fl.url, "http://127.0.0.1:3100/") {
			t.Fatalf("form sent to %q (%s)", fl.url, fl.path)
		}
	})
}

// flashApp is a login like Rails 8's generated one and Laravel Breeze's
// (measured 2026-11-23): a wrong login and a limited one get the same
// redirect back to the login page, and only the message the session
// cookie carries there, shown once, tells them apart. The limit counts
// every login from the address, as Rails' rate_limit does.
type flashApp struct {
	mu     sync.Mutex
	posts  int
	limit  int
	follow int
}

func (a *flashApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/session/new":
		msg := ""
		if c, err := r.Cookie("flash"); err == nil {
			a.follow++
			msg = map[string]string{"bad": "Try another email address or password.", "limit": "Try again later."}[c.Value]
			http.SetCookie(w, &http.Cookie{Name: "flash", Path: "/", MaxAge: -1})
		}
		http.SetCookie(w, &http.Cookie{Name: "_app_session", Value: "s1", Path: "/"})
		fmt.Fprintf(w, `<p>%s</p><form action="/session" method="post"><input type="hidden" name="authenticity_token" value="t1"><input name="email_address"><input type="password" name="password"><input type="submit" name="commit" value="Sign in"></form>`, msg)
	case r.Method == http.MethodPost && r.URL.Path == "/session":
		if c, err := r.Cookie("_app_session"); err != nil || c.Value != "s1" || r.FormValue("authenticity_token") != "t1" {
			http.Error(w, "csrf", http.StatusUnprocessableEntity)
			return
		}
		a.posts++
		flash := "bad"
		switch {
		case a.limit > 0 && a.posts > a.limit:
			flash = "limit"
		case r.FormValue("password") == right:
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "flash", Value: flash, Path: "/"})
		http.Redirect(w, r, "http://"+r.Host+"/session/new", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

// Before ADR 0062's redirect reading, a limit shown only after the
// redirect was a false "not limited" (Rails 8.1.4.1 and Laravel 12.73
// with Breeze 2.4.2, measured 2026-11-23).
func TestFormFlashLimit(t *testing.T) {
	a := &flashApp{}
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	_, cfg := serveForm(t, &formApp{})
	tu := mustTarget(t, srv.URL+"/")
	cfg.Target = tu
	l, err := ParsePage(tu.Origin()+"/session/new", "tester@shop.test", "email_address={user}&password={password}", tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), cfg, l, 5, right)
	if err != nil || r.Limited || r.Requests != 2+3*5 || a.follow != 5 || r.Redirect != tu.Origin()+"/session/new" {
		t.Fatalf("no limit: %+v %v, %d follows", r, err, a.follow)
	}
	a.posts, a.follow, a.limit = 0, 0, 4
	r, err = Check(context.Background(), cfg, l, 8, right)
	if err != nil || !r.Limited || r.Attempts != 4 || r.Signal != `the page it redirected to says "try again later"` || Findings(l, r, 8) != nil {
		t.Fatalf("limit: %+v %v", r, err)
	}
	sr, err := Spray(context.Background(), cfg, l, 8, r)
	if err != nil || !sr.Limited || sr.Attempts != 1 || !strings.Contains(sr.Signal, "the answer that showed login-throttle's limit") {
		t.Fatalf("spray: %+v %v", sr, err)
	}
	// A limit that holds before the run, seen only after the redirect.
	a.limit = 1 // every login from now on is limited, the right one too
	r, err = Check(context.Background(), cfg, l, 8, right)
	if err != nil || !r.Limited || r.Attempts != 1 || !strings.Contains(r.Signal, `redirected to says "try again later", already at the first login`) {
		t.Fatalf("already limited: %+v %v", r, err)
	}
}
