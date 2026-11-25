package ratelimit

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

// signupApp is a sign-up page like a Next.js Server Action form (measured
// on Next.js 16.4.6 for ADR 0069): the page has a form with a hidden
// action field and sets a cookie, the form is sent as multipart, and any
// other POST gets the page back, unprocessed. A sign-up that runs
// redirects with 303 to where, or answers as, the mode says; after limit
// sign-ups it says so the same way.
type signupApp struct {
	mu    sync.Mutex
	mode  string // "redirect", "account" (a redirect naming the account), "flash", "state" (200 with the form's state)
	limit int
	runs  int
	reads int
	posts int
}

const signupPage = `<form><input name=email type=email><input name=password type=password><button name="$ACTION_ID_abc123" formAction="" formEncType="multipart/form-data" formMethod="POST">Sign up</button></form>`

func (a *signupApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/signup":
		a.reads++
		msg := ""
		if c, err := r.Cookie("flash"); err == nil && c.Value == "limit" {
			msg = "<p>Too many sign-ups, try again later.</p>"
		}
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: fmt.Sprint(a.reads), Path: "/"})
		io.WriteString(w, msg+signupPage)
		return
	case r.Method == http.MethodGet:
		io.WriteString(w, "<p>Welcome</p>")
		return
	case r.URL.Path != "/signup":
		http.NotFound(w, r)
		return
	}
	a.posts++
	if err := r.ParseMultipartForm(1 << 20); err != nil || r.MultipartForm.Value["$ACTION_ID_abc123"] == nil {
		io.WriteString(w, signupPage) // not run: the page again
		return
	}
	if c, err := r.Cookie("csrf"); err != nil || c.Value != fmt.Sprint(a.reads) || r.Header.Get("Origin") != "http://"+r.Host {
		http.Error(w, "csrf", http.StatusInternalServerError)
		return
	}
	a.runs++
	limited := a.limit > 0 && a.runs > a.limit
	switch a.mode {
	case "redirect":
		if limited {
			http.Redirect(w, r, "/signup?error=too-many-attempts", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/signup?notice=check-email", http.StatusSeeOther)
	case "account":
		name, _, _ := strings.Cut(r.FormValue("email"), "@")
		http.Redirect(w, r, "/users/"+name+"/welcome", http.StatusSeeOther)
	case "flash":
		v := "ok"
		if limited {
			v = "limit"
		}
		http.SetCookie(w, &http.Cookie{Name: "flash", Value: v, Path: "/"})
		http.Redirect(w, r, "http://"+r.Host+"/signup", http.StatusFound)
	case "state":
		io.WriteString(w, "<p>Check your email.</p>"+signupPage)
	}
}

func serveSignup(t *testing.T, h http.Handler) (*target.URL, egress.Config) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tu := mustTarget(t, srv.URL+"/")
	old := sleep
	t.Cleanup(func() { sleep = old })
	sleep = func(context.Context, time.Duration) error { return nil }
	return tu, egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
}

const signupFields = "email={new}%40example.com&password=Abcdef123456"

func TestParsePageForm(t *testing.T) {
	tu := mustTarget(t, "http://127.0.0.1:3100/")
	e, err := ParsePageForm(SignUp, "http://127.0.0.1:3100/signup?next=%2F", signupFields, tu)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Form || e.From != "--signup-page" || e.URL != "http://127.0.0.1:3100/signup?next=%2F" || e.Path != "/signup?next=%2F" || len(e.fields) != 2 || e.fields[0].Value != "{new}@example.com" {
		t.Errorf("%+v", e)
	}
	if b := string(e.formBody("w", "siegekit-new-x")); b != "email=siegekit-new-x%40example.com&password=Abcdef123456" {
		t.Error(b)
	}
	for _, c := range []struct {
		p                Page
		page, body, want string
	}{
		{SignUp, "http://127.0.0.1:3101/signup", signupFields, "not on the target's origin"},
		{SignUp, "http://127.0.0.1:3100/signup#x", signupFields, "fragment"},
		{SignUp, "http://127.0.0.1:3100/signup", "", "--signup-page needs --signup-body"},
		{SignUp, "http://127.0.0.1:3100/signup", "email=me%40x.test", "must contain {new}"},
		{SignUp, "http://127.0.0.1:3100/signup", `{"email":"{new}@x.test"}`, "names the form's fields as a form body"},
		{SignUp, "http://127.0.0.1:3100/signup", "a=1&{new}=x", "in a field name"},
		{SignUp, "http://127.0.0.1:3100/signup", "email={new}&email=x", "twice"},
		{Reset, "http://127.0.0.1:3100/forgot", "email={new}", "may contain {wrong} but not {new}"},
		{Reset, "http://127.0.0.1:3100/forgot", "email=%zz", "not a valid form body"},
		{Code, "http://127.0.0.1:3100/2fa", "code={wrong}", "no page flag"},
	} {
		if _, err := ParsePageForm(c.p, c.page, c.body, tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s %s: %v, want %q", c.p, c.page, c.body, err, c.want)
		}
	}
}

// Issue #81: a sign-up page posted as a plain form, as --signup-url sends
// it, gets the page back and never runs. Before ADR 0069 that was "No
// limit seen in 20 sign-ups"; now the answers match the page's own GET,
// so nothing is reported and the result says why.
func TestFormPageUnreached(t *testing.T) {
	a := &signupApp{mode: "redirect", limit: 10}
	tu, cfg := serveSignup(t, a)
	e, err := ParsePage(SignUp, tu.Origin()+"/signup", "%24ACTION_ID_abc123=&"+signupFields, tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), cfg, e, DefaultRequests)
	if err != nil || r.Limited || r.Requests != 20 || r.Reads != 1 || r.Reached != "" || a.runs != 0 || len(Findings(e, r, DefaultRequests)) != 0 {
		t.Fatalf("%+v %v, %d runs", r, err, a.runs)
	}
	if s := r.Summary(DefaultRequests); !strings.HasSuffix(s, "; no answer below 400 differed from the page's own answer to a GET in status, redirect or a new cookie, so SiegeKit cannot tell that its requests reached the app's sign-up code: not reported. Give --mail-catcher to count the emails. A form that only a browser can send (a Next.js Server Action, a CSRF token) needs --signup-page") {
		t.Error(s)
	}
}

func TestFormPage(t *testing.T) {
	check := func(a *signupApp, n int) (*Endpoint, Result, error) {
		t.Helper()
		tu, cfg := serveSignup(t, a)
		e, err := ParsePageForm(SignUp, tu.Origin()+"/signup", signupFields, tu)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Check(context.Background(), cfg, e, n)
		return e, r, err
	}
	// The limit shows only in the redirect: the same 303 to another page.
	a := &signupApp{mode: "redirect", limit: 10}
	e, r, err := check(a, DefaultRequests)
	if err != nil || !r.Limited || r.Requests != 11 || a.runs != 11 || r.Reads != 22 || r.Signal != "redirected to /signup?error=too-many-attempts instead of /signup?notice=check-email" ||
		!strings.HasPrefix(r.Form, "sent to http://127.0.0.1:") || !strings.HasSuffix(r.Form, `/signup as multipart/form-data, button "Sign up"`) || len(Findings(e, r, DefaultRequests)) != 0 {
		t.Fatalf("redirect: %+v %v, %d runs", r, err, a.runs)
	}
	if len(r.To) != 11 || !strings.HasPrefix(r.To[0], "siegekit-new-") {
		t.Errorf("addresses %q", r.To)
	}
	// No limit, and each redirect names the account made: the request's
	// own name is not a limit, and the answers differ from the page's GET.
	a = &signupApp{mode: "account"}
	e, r, err = check(a, DefaultRequests)
	if err != nil || r.Limited || r.Requests != 20 || a.runs != 20 || r.Reached != "an answer (answered 303 to /users/{new}/welcome) differed from the page's own answer to a GET (answered 200 setting the cookies csrf)" {
		t.Fatalf("account: %+v %v", r, err)
	}
	if fs := Findings(e, r, DefaultRequests); len(fs) != 1 || fs[0].RuleID != "signup-not-limited" || !strings.Contains(fs[0].Message, "SiegeKit knows they reached the app: an answer (answered 303 to /users/{new}/welcome) differed") {
		t.Errorf("account: %+v", fs)
	}
	// The limit shows only on the page the redirect names (Rails' and
	// Laravel's flash messages, as for logins in ADR 0062).
	a = &signupApp{mode: "flash", limit: 4}
	_, r, err = check(a, DefaultRequests)
	if err != nil || !r.Limited || r.Requests != 5 || r.Signal != `the page it redirected to has the limit word "too many"` {
		t.Fatalf("flash: %+v %v", r, err)
	}
	// useActionState: 200 with the form's state, as the page itself is: no
	// sign of reaching the app without an email (a missed finding, not a
	// false one), and the result names no page flag, which was given. The
	// page sets a cookie that the answer, sent with it, does not set
	// again: no difference.
	a = &signupApp{mode: "state"}
	e, r, err = check(a, DefaultRequests)
	if err != nil || r.Limited || a.runs != 20 || r.Reached != "" || len(Findings(e, r, DefaultRequests)) != 0 || strings.Contains(r.Summary(DefaultRequests), "needs --signup-page") {
		t.Fatalf("state: %+v %v %q", r, err, r.Summary(DefaultRequests))
	}
	r.Mail = &Mail{Catcher: "http://127.0.0.1:8025/", Emails: 20, Settled: true}
	if fs := Findings(e, r, DefaultRequests); len(fs) != 1 || !strings.Contains(fs[0].Message, "emails arrived for them at the mail catcher") {
		t.Errorf("state with mail: %+v", fs)
	}
}

func TestFormPageFails(t *testing.T) {
	for _, c := range []struct {
		name string
		page func(n int) (int, string) // the page's n-th read (from 1), 0 for the app's own
		want string
		lim  bool
	}{
		{"first page redirects", func(int) (int, string) { return 302, "" }, "the sign-up page answered 302; --signup-page must be the page with the form itself", false},
		{"no form", func(int) (int, string) { return 200, "<p>JavaScript needed</p>" }, "--signup-page: no form SiegeKit can send", false},
		{"page 429 later", func(n int) (int, string) {
			if n > 3 {
				return 429, ""
			}
			return 0, ""
		}, "the sign-up page answered 429", true},
		{"captcha appears", func(n int) (int, string) {
			if n > 3 {
				return 200, "<p>Please solve the CAPTCHA</p>" + signupPage
			}
			return 0, ""
		}, `the sign-up page has the limit word "captcha"`, true},
		{"page 500 later", func(n int) (int, string) {
			if n > 3 {
				return 500, ""
			}
			return 0, ""
		}, "the sign-up page answered 500 (a server error) after 3 request(s)", false},
		{"form gone", func(n int) (int, string) {
			if n > 3 {
				return 200, "<p>Maintenance</p>"
			}
			return 0, ""
		}, "after 3 request(s) the form on the sign-up page could not be sent", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := &signupApp{mode: "account"}
			reads := 0
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/signup" {
					reads++
					if s, b := c.page(reads); s != 0 {
						w.WriteHeader(s)
						io.WriteString(w, b)
						return
					}
					a.reads = reads - 1
				}
				a.ServeHTTP(w, r)
			})
			tu, cfg := serveSignup(t, h)
			e, _ := ParsePageForm(SignUp, tu.Origin()+"/signup", signupFields, tu)
			r, err := Check(context.Background(), cfg, e, 10)
			if c.lim {
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

// Juice Shop's sign-up (measured, ADR 0069): 201 with Location naming the
// account made (/api/Users/27, then /28). Reading Location on any status
// made that a false "limit after 3"; only a 3xx's Location is read.
func TestLocationOnlyOnRedirects(t *testing.T) {
	id := 26
	tu, cfg := serveSignup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		id++
		w.Header().Set("Location", fmt.Sprintf("/api/Users/%d", id))
		w.WriteHeader(http.StatusCreated)
	}))
	e, err := ParsePage(SignUp, tu.Origin()+"/api/Users", `{"email":"{new}@example.com","password":"Abcdef12345!"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Check(context.Background(), cfg, e, DefaultRequests)
	if err != nil || r.Limited || r.Requests != 20 || r.Reads != 1 || r.Reached != "an answer (answered 201) differed from the page's own answer to a GET (answered 401)" || len(Findings(e, r, DefaultRequests)) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDiffers(t *testing.T) {
	page := webform.Shape{Status: 200, Cookies: "_csrf,i_like_gitea"}
	for _, c := range []struct {
		a    webform.Shape
		want bool
	}{
		{webform.Shape{Status: 200}, false},                                // the page's cookies not set again
		{webform.Shape{Status: 200, Cookies: "_csrf,i_like_gitea"}, false}, // set again
		{webform.Shape{Status: 200, Cookies: "_csrf,sb-auth-token"}, true}, // a new cookie
		{webform.Shape{Status: 303, Location: "/"}, true},                  // another status
		{webform.Shape{Status: 200, Location: "/x"}, true},                 // another redirect
	} {
		if got := differs(c.a, page); got != c.want {
			t.Errorf("%+v: %v", c.a, got)
		}
	}
	if differs(webform.Shape{Status: 200}, webform.Shape{Status: 200}) || !differs(webform.Shape{Status: 200, Cookies: "s"}, webform.Shape{Status: 200}) {
		t.Error("no cookies")
	}
}
