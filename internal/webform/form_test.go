package webform

import (
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
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

var tmpl = []Field{{"email", "{user}"}, {"password", "{password}"}}

func buildPage(t *testing.T, html, pageURL string) (*Submission, error) {
	t.Helper()
	tu := mustTarget(t, "http://127.0.0.1:3100/")
	pu, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	return Read([]byte(html)).Build(pu, tu, tmpl, strings.NewReplacer("{user}", "a@b.test", "{password}", "pw&x=1"))
}

// entries decodes a built body into name=value pairs, in order.
func entries(t *testing.T, fl *Submission) []string {
	t.Helper()
	var out []string
	mt, params, _ := mime.ParseMediaType(fl.ContentType)
	switch mt {
	case "multipart/form-data":
		r := multipart.NewReader(strings.NewReader(string(fl.Body)), params["boundary"])
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
		for kv := range strings.SplitSeq(string(fl.Body), "&") {
			k, v, _ := strings.Cut(kv, "=")
			k, _ = url.QueryUnescape(k)
			v, _ = url.QueryUnescape(v)
			out = append(out, k+"="+v)
		}
	default:
		t.Fatalf("content type %q", fl.ContentType)
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
	if got := entries(t, fl); !slices.Equal(got, want) || fl.Path != "/login" || fl.Button != "Log in" || fl.Describe() != `multipart/form-data, button "Log in"` {
		t.Errorf("%v %+v", got, fl)
	}
	fl, err = buildPage(t, nextStatePage, "http://127.0.0.1:3100/login2")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"$ACTION_REF_1=", `$ACTION_1:0={"id":"60df375f7767b6d2657ac67c5bf0468db77c036ad2","bound":"$@1"}`, "$ACTION_1:1=[null]", "$ACTION_KEY=k1d9d0146a2efa55bcf671ea1b28919fd", "email=a@b.test", "password=pw&x=1"} // gitleaks:allow (the action key of a page Next.js rendered for the test, not a secret)
	if got := entries(t, fl); !slices.Equal(got, want) || fl.Path != "/login2" {
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
			if got := entries(t, fl); !slices.Equal(got, c.want) || fl.Path != c.path {
				t.Errorf("got %v %s, want %v %s", got, fl.Path, c.want, c.path)
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
	if got := Cookies(h, "127.0.0.1", "/accounts/login", "/accounts/login", n); got != "csrftoken=def; dir=1" {
		t.Error(got)
	}
	if got := Cookies(h, "app.example.test", "/login", "/api/x", n); got != "csrftoken=def; api=1; dir=1; sub=1" { // the default path of /login is /
		t.Error(got)
	}
	if got := Cookies(h, "127.0.0.1", "/login", "/apix", n); got != "csrftoken=def; dir=1" {
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
		if got := Redirect(&egress.Answer{Header: http.Header{"Location": {in}}}); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
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
		fl, err := Read([]byte(s)).Build(pu, tu, tmpl, strings.NewReplacer("{user}", "u", "{password}", "p"))
		if err != nil {
			return
		}
		if !target.SendablePath(fl.Path) || !strings.HasPrefix(fl.URL, "http://127.0.0.1:3100/") {
			t.Fatalf("form sent to %q (%s)", fl.URL, fl.Path)
		}
	})
}

func mustTarget(t *testing.T, raw string) *target.URL {
	t.Helper()
	u, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
