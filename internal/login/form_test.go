package login

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/webform"
)

func TestParsePage(t *testing.T) {
	tu := mustTarget(t, "http://127.0.0.1:3100/")
	l, err := ParsePage("http://127.0.0.1:3100/login?next=%2F", "a@b.test", "email={user}&password={password}&remember=on", tu)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Page || l.URL != "http://127.0.0.1:3100/login?next=%2F" || l.Path != "/login?next=%2F" || len(l.fields) != 3 || l.fields[2] != (webform.Field{Name: "remember", Value: "on"}) {
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
		}, "", `the login page has the limit word "captcha"`, true},
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
			msg = map[string]string{"bad": "Try another email address or password.", "limit": "Too many attempts, try again later."}[c.Value]
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
	if err != nil || !r.Limited || r.Attempts != 4 || r.Signal != `the page it redirected to has the limit word "too many"` || Findings(l, r, 8) != nil {
		t.Fatalf("limit: %+v %v", r, err)
	}
	sr, err := Spray(context.Background(), cfg, l, 8, r)
	if err != nil || !sr.Limited || sr.Attempts != 1 || !strings.Contains(sr.Signal, `the answer that showed login-throttle's limit (answered 302 to `+tu.Origin()+`/session/new setting the cookies flash, and the page it redirected to has the limit words "too many" and "try again later"), so the limit holds`) {
		t.Fatalf("spray: %+v %v", sr, err)
	}
	// A limit that holds before the run, seen only after the redirect.
	a.limit = 1 // every login from now on is limited, the right one too
	r, err = Check(context.Background(), cfg, l, 8, right)
	if err != nil || !r.Limited || r.Attempts != 1 || !strings.Contains(r.Signal, `redirected to has the limit word "too many", already at the first login`) {
		t.Fatalf("already limited: %+v %v", r, err)
	}
}
