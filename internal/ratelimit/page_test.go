package ratelimit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

func TestParsePage(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	e, err := ParsePage(Code, "http://localhost:3000/rest/2fa/verify", `{"tmpToken":"t","totpToken":"{wrong}"}`, tu)
	if err != nil || e.Method != http.MethodPost || e.Page != Code || e.From != "--code-url" || e.ContentType() != "application/json" {
		t.Fatalf("%+v %v", e, err)
	}
	a, b := string(e.next()), string(e.next())
	if a == b || !strings.Contains(a, `"totpToken":"siegekit-wrong-`) || !strings.Contains(a, `"tmpToken":"t"`) || !json.Valid([]byte(a)) {
		t.Errorf("bodies %s %s", a, b)
	}
	s, err := ParsePage(SignUp, "http://localhost:3000/user/sign_up", "user_name={new}&email={new}%40example.com&password=p", tu)
	if err != nil || s.ContentType() != "application/x-www-form-urlencoded" {
		t.Fatalf("%+v %v", s, err)
	}
	v, err := url.ParseQuery(string(s.next()))
	if err != nil || !strings.HasPrefix(v.Get("user_name"), "siegekit-new-") || v.Get("email") != v.Get("user_name")+"@example.com" || v.Get("password") != "p" {
		t.Errorf("sign-up body %v %v", v, err)
	}
	// A reset may hold no placeholder: Gitea's sends only an address.
	if r, err := ParsePage(Reset, "http://localhost:3000/user/forgot_password", "email=a%40b.test", tu); err != nil || string(r.next()) != "email=a%40b.test" {
		t.Errorf("reset %v %v", r, err)
	}
	for _, c := range []struct {
		p         Page
		url, body string
		want      string
	}{
		{Reset, "http://localhost:3000/r", "", "--reset-url needs --reset-body"},
		{Code, "http://localhost:3000/c", `{"code":"123456"}`, "must contain {wrong}"},
		{SignUp, "http://localhost:3000/s", `{"email":"me@x.test"}`, "must contain {new}"},
		{Reset, "http://localhost:3000/r", `{"email":"{new}"}`, "not {new}"},
		{SignUp, "http://localhost:3000/s", `{"email":"{new}","x":"{wrong}"}`, "not {wrong}"},
		{Code, "http://localhost:3000/c", `{"code":{wrong}}`, "inside quotes"},
		{Code, "http://localhost:3000/c", "code={wrong}&x=%zz", "not valid JSON or a valid form body"},
		{Code, "http://evil.test/c", "code={wrong}", "not on the target's origin"},
		{Code, "http://localhost:3000//evil.test/", "code={wrong}", "single /"},
		{Reset, "http://localhost:3000/r", "a=" + strings.Repeat("x", maxBody), "longer than"},
	} {
		if _, err := ParsePage(c.p, c.url, c.body, tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParsePage(%s, %q, %.40q): %v, want %q", c.p, c.url, c.body, err, c.want)
		}
	}
}

// har builds a HAR file of POST requests: method, URL, MIME type, body.
func har(entries ...[4]string) []byte {
	type pd struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	}
	type req struct {
		Method   string `json:"method"`
		URL      string `json:"url"`
		PostData *pd    `json:"postData,omitempty"`
	}
	var es []map[string]any
	for _, e := range entries {
		r := req{Method: e[0], URL: e[1]}
		if e[3] != "" {
			r.PostData = &pd{e[2], e[3]}
		}
		es = append(es, map[string]any{"request": r})
	}
	b, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": es}})
	return b
}

const jsonMIME, formMIME = "application/json", "application/x-www-form-urlencoded"

// TestPagesFromHAR uses the bodies of the Chromium recordings of
// 2026-11-22 (ADR 0055): Juice Shop v20.4.0 and Gitea 1.24.6.
func TestPagesFromHAR(t *testing.T) {
	js := mustTarget(t, "http://127.0.0.1:3000/")
	h, err := PagesFromHAR(har(
		[4]string{"POST", "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&t=x&sid=y", "text/plain;charset=UTF-8", "40"},
		[4]string{"POST", "http://127.0.0.1:3000/api/Users/", jsonMIME, `{"email":"rec-a@siegekit.test","password":"Passw0rd!x1","passwordRepeat":"Passw0rd!x1","securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},"securityAnswer":"blue"}`},
		[4]string{"POST", "http://127.0.0.1:3000/api/SecurityAnswers/", jsonMIME, `{"UserId":26,"answer":"blue","SecurityQuestionId":1}`},
		[4]string{"POST", "http://127.0.0.1:3000/rest/user/reset-password", jsonMIME, `{"email":"rec-a@siegekit.test","answer":"blue","new":"Passw0rd!x2","repeat":"Passw0rd!x2"}`},
		[4]string{"POST", "http://127.0.0.1:3000/rest/user/login", jsonMIME, `{"email":"wurstbrot@juice-sh.op","password":"x"}`},
		[4]string{"POST", "http://127.0.0.1:3000/rest/2fa/verify", jsonMIME, `{"tmpToken":"eyJ.x.y","totpToken":"192503"}`},
		[4]string{"POST", "http://127.0.0.1:3000/rest/2fa/verify", jsonMIME, `{"tmpToken":"eyJ.x.y","totpToken":"192504"}`},
		[4]string{"POST", "http://other.test/rest/user/reset-password", jsonMIME, `{"email":"a@b.test"}`},
	), js, "a.har")
	if err != nil || len(h.Pages) != 3 || h.More[Code] != 1 || len(h.Unusable) != 0 {
		t.Fatalf("%+v %v", h, err)
	}
	reset := h.Pages[Reset]
	var m map[string]any
	if reset.URL != "http://127.0.0.1:3000/rest/user/reset-password" || reset.From != "a.har" || json.Unmarshal(reset.next(), &m) != nil {
		t.Fatalf("reset %+v", reset)
	}
	// The address stays; every other value is a new wrong guess, so the
	// recorded (right) answer and new password are never sent.
	if m["email"] != "rec-a@siegekit.test" || m["answer"] == "blue" || !strings.HasPrefix(m["answer"].(string), "siegekit-wrong-") || m["new"] == "Passw0rd!x2" || m["new"] != m["repeat"] {
		t.Errorf("reset body %v", m)
	}
	m = nil
	if json.Unmarshal(h.Pages[SignUp].next(), &m) != nil || !strings.HasPrefix(m["email"].(string), "siegekit-new-") || !strings.HasSuffix(m["email"].(string), "@example.com") ||
		m["password"] != "Passw0rd!x1" || m["securityAnswer"] != "blue" || m["securityQuestion"].(map[string]any)["id"] != 1.0 {
		t.Errorf("sign-up body %v", m)
	}
	m = nil
	if json.Unmarshal(h.Pages[Code].next(), &m) != nil || m["tmpToken"] != "eyJ.x.y" || !strings.HasPrefix(m["totpToken"].(string), "siegekit-wrong-") {
		t.Errorf("code body %v", m)
	}

	gt := mustTarget(t, "http://127.0.0.1:3001/")
	h, err = PagesFromHAR(har(
		[4]string{"POST", "http://127.0.0.1:3001/user/sign_up", formMIME, "_csrf=tok1&user_name=reca&email=reca%40siegekit.test&password=Passw0rd%21x1&retype=Passw0rd%21x1"},
		[4]string{"POST", "http://127.0.0.1:3001/user/forgot_password", formMIME, "_csrf=tok2&email=alice%40siegekit.test"},
		[4]string{"POST", "http://127.0.0.1:3001/user/login", formMIME, "_csrf=tok2&user_name=alice&password=Passw0rd%21x1"},
		[4]string{"POST", "http://127.0.0.1:3001/user/two_factor", formMIME, "_csrf=tok3&passcode=400031"},
	), gt, "g.har")
	if err != nil || len(h.Pages) != 3 {
		t.Fatalf("%+v %v", h, err)
	}
	if b := string(h.Pages[Reset].next()); b != "_csrf=tok2&email=alice%40siegekit.test" {
		t.Errorf("reset %s", b)
	}
	v, _ := url.ParseQuery(string(h.Pages[SignUp].next()))
	if v.Get("_csrf") != "tok1" || !strings.HasPrefix(v.Get("user_name"), "siegekit-new-") || v.Get("email") == "reca@siegekit.test" || v.Get("password") != "Passw0rd!x1" || v.Get("retype") != "Passw0rd!x1" {
		t.Errorf("sign-up %v", v)
	}
	v, _ = url.ParseQuery(string(h.Pages[Code].next()))
	if v.Get("_csrf") != "tok3" || !strings.HasPrefix(v.Get("passcode"), "siegekit-wrong-") {
		t.Errorf("code %v", v)
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		path, mime, body string
		want             Page
	}{
		// Writes of the gate's recordings (2026-11-22): none is a page.
		{"/rest/user/login", jsonMIME, `{"email":"a","password":"b"}`, ""},
		{"/api/BasketItems/", jsonMIME, `{"ProductId":1,"BasketId":"6","quantity":1}`, ""},
		{"/api/Addresss/", jsonMIME, `{"country":"X","zipCode":"1"}`, ""},
		{"/api/Cards/", jsonMIME, `{"fullName":"A","cardNum":1}`, ""},
		{"/rest/basket/7/checkout", jsonMIME, `{}`, ""},
		{"/alice/priv/issues/new", formMIME, "_csrf=t&title=x", ""},
		{"/-/fetch-redirect", formMIME, "_csrf=t", ""},
		// Pages that change the second factor or a password are not
		// these pages.
		{"/rest/2fa/setup", jsonMIME, `{"password":"p","setupToken":"s","initialToken":"1"}`, ""},
		{"/user/settings/security/two_factor/enroll", formMIME, "passcode=1", ""},
		{"/rest/2fa/disable", jsonMIME, `{"password":"p"}`, ""},
		{"/api/cart/reset", jsonMIME, `{"x":1}`, ""},
		{"/api/presets", jsonMIME, `{"x":1}`, ""},
		{"/user/settings/account", formMIME, "old_password=a&password=b&retype=b", ""},
		{"/api/users/me/password", jsonMIME, `{"password":"a","passwordRepeat":"a"}`, ""},
		// Pages.
		{"/rest/user/reset-password", jsonMIME, `{}`, Reset},
		{"/user/forgot_password", formMIME, "email=a", Reset},
		{"/wp-login.php?action=lostpassword", formMIME, "user_login=a", Reset},
		{"/api/auth/resetPassword", jsonMIME, `{}`, Reset},
		{"/user/recover_account", formMIME, "token=t&password=p", Reset},
		{"/user/sign_up", formMIME, "user_name=a", SignUp},
		{"/api/auth/signUp", jsonMIME, `{}`, SignUp},
		{"/register", formMIME, "u=a", SignUp},
		{"/api/Users/", jsonMIME, `{"email":"a","password":"b","passwordRepeat":"b"}`, SignUp},
		{"/rest/2fa/verify", jsonMIME, `{"tmpToken":"t","totpToken":"1"}`, Code},
		{"/user/two_factor", formMIME, "passcode=1", Code},
		{"/api/mfa", jsonMIME, `{"otp":"1"}`, Code},
		{"/api/auth/verify", jsonMIME, `{"code":"123456"}`, Code},
		{"/api/auth/verify", jsonMIME, `{"email":"a"}`, ""},
	} {
		if got := classify(c.path, c.mime, c.body); got != c.want {
			t.Errorf("classify(%s, %s) = %q, want %q", c.path, c.body, got, c.want)
		}
	}
}

func TestPagesFromHARUnusable(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	h, err := PagesFromHAR(har(
		[4]string{"POST", "http://localhost:3000/api/mfa", jsonMIME, `{"factor":"x"}`},
		[4]string{"POST", "http://localhost:3000/register", jsonMIME, `{"password":"p"}`},
		[4]string{"POST", "http://localhost:3000/forgot", "multipart/form-data; boundary=x", "--x--"},
		[4]string{"POST", "http://localhost:3000/forgot", jsonMIME, `{"email":"{wrong}"}`},
		[4]string{"POST", "http://localhost:3000/2fa", jsonMIME, `[1]`},
	), tu, "a.har")
	if err != nil || len(h.Pages) != 0 {
		t.Fatalf("%+v %v", h, err)
	}
	for p, want := range map[Page]string{Code: "named like a code", SignUp: "user name or an email address", Reset: "not JSON or a form"} {
		if !strings.Contains(h.Unusable[p], want) {
			t.Errorf("%s: %q, want %q", p, h.Unusable[p], want)
		}
	}
	// A later usable page of the same kind is taken.
	h, _ = PagesFromHAR(har(
		[4]string{"POST", "http://localhost:3000/api/mfa", jsonMIME, `{"factor":"x"}`},
		[4]string{"POST", "http://localhost:3000/api/mfa/verify", jsonMIME, `{"code":123456}`},
	), tu, "a.har")
	if e := h.Pages[Code]; e == nil || h.Unusable[Code] != "" || !strings.Contains(string(e.next()), `"code":"siegekit-wrong-`) {
		t.Errorf("%+v", h)
	}
	if _, err := PagesFromHAR([]byte("{"), tu, "a.har"); err == nil {
		t.Error("broken HAR accepted")
	}
}

func TestLimitNumber(t *testing.T) {
	for _, c := range []struct {
		h    http.Header
		want int
	}{
		{http.Header{}, 0},
		{http.Header{"X-Ratelimit-Limit": {"100"}}, 100},
		{http.Header{"Ratelimit-Limit": {"5, 5;w=60"}}, 5},
		{http.Header{"Ratelimit-Limit": {"x"}, "X-Ratelimit-Limit": {"7"}}, 7},
		{http.Header{"X-Ratelimit-Limit": {"0"}}, 0},
		{http.Header{"Ratelimit": {"limit=100"}}, 0},
	} {
		if got := LimitNumber(c.h); got != c.want {
			t.Errorf("LimitNumber(%v) = %d, want %d", c.h, got, c.want)
		}
	}
}

func pageEndpoint(t *testing.T, p Page, body string) (*Endpoint, egress.Config) {
	_, cfg := testEndpoint(t, "")
	pe, err := ParsePage(p, "http://localhost:3000/page", body, cfg.Target)
	if err != nil {
		t.Fatal(err)
	}
	return pe, cfg
}

// installPage replaces send for a page: bodies differ on each request.
func installPage(t *testing.T, e *Endpoint, answer func(i int) *egress.Answer) *[]string {
	var f fake
	f.install(t, e, nil)
	var bodies []string
	send = func(ctx context.Context, cfg egress.Config, method, path, ct string, body []byte, max int64) (*egress.Answer, error) {
		if method != http.MethodPost || path != e.Path || ct != e.ContentType() {
			t.Errorf("sent %s %s %s", method, path, ct)
		}
		bodies = append(bodies, string(body))
		a := answer(len(bodies) - 1)
		if a.Header == nil {
			a.Header = http.Header{}
		}
		return a, nil
	}
	return &bodies
}

func TestCheckPage(t *testing.T) {
	// A reset or code page answers a wrong guess with 401: a valid
	// baseline there, not "behind a login".
	for _, p := range []Page{Reset, Code} {
		e, cfg := pageEndpoint(t, p, `{"email":"me@x.test","answer":"{wrong}"}`)
		bodies := installPage(t, e, func(int) *egress.Answer { return answer(401, nil) })
		r, err := Check(context.Background(), cfg, e, 5)
		if err != nil || r.Limited || r.Requests != 5 || r.Baseline != 401 || r.Accepted != 0 || r.Changed != 0 {
			t.Fatalf("%s: %+v %v", p, r, err)
		}
		seen := map[string]bool{}
		for _, b := range *bodies {
			if seen[b] || !strings.Contains(b, `"answer":"siegekit-wrong-`) {
				t.Errorf("%s: body %s", p, b)
			}
			seen[b] = true
		}
	}
	// A sign-up that is refused made no account: the check fails.
	e, cfg := pageEndpoint(t, SignUp, `{"email":"{new}@x.test"}`)
	installPage(t, e, func(int) *egress.Answer { return answer(400, nil) })
	if _, err := Check(context.Background(), cfg, e, 5); err == nil || !strings.Contains(err.Error(), "the sign-up answered 400, so it made no account") {
		t.Errorf("sign-up 400: %v", err)
	}
	installPage(t, e, func(int) *egress.Answer { return answer(401, nil) })
	if _, err := Check(context.Background(), cfg, e, 5); err == nil || !strings.Contains(err.Error(), "needs a login") {
		t.Errorf("sign-up 401: %v", err)
	}
	// Accepted sign-ups are counted; a later change of status is not
	// reported as "not limited".
	installPage(t, e, func(i int) *egress.Answer {
		if i >= 3 {
			return answer(400, nil)
		}
		return answer(201, nil)
	})
	r, err := Check(context.Background(), cfg, e, 5)
	if err != nil || r.Limited || r.Accepted != 3 || r.Changed != 2 || len(Findings(e, r, 5)) != 0 || !strings.Contains(r.Summary(5), "2 answered a status other than the first answer's 201") {
		t.Errorf("changed: %+v %v %q", r, err, r.Summary(5))
	}
	// The same holds for --rate-limit-url.
	g, gcfg := testEndpoint(t, "")
	var f fake
	f.install(t, g, func(i int) (*egress.Answer, error) {
		if i == 2 {
			return answer(400, nil), nil
		}
		return answer(200, nil), nil
	})
	if r, err := Check(context.Background(), gcfg, g, 3); err != nil || r.Changed != 1 || len(Findings(g, r, 3)) != 0 {
		t.Errorf("rate-limit changed: %+v %v", r, err)
	}
	// A header's limit number is kept.
	c, ccfg := pageEndpoint(t, Code, `{"code":"{wrong}"}`)
	installPage(t, c, func(int) *egress.Answer { return answer(401, http.Header{"X-Ratelimit-Limit": {"100"}}) })
	r, err = Check(context.Background(), ccfg, c, 5)
	if err != nil || !r.Limited || r.Limit != 100 || r.Requests != 1 || !strings.HasSuffix(r.Summary(5), "(limit 100)") {
		t.Errorf("limit number: %+v %v", r, err)
	}
}

func TestPageFindings(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	mk := func(p Page) *Endpoint {
		body := map[Page]string{Reset: "email=a%40b.test", SignUp: "u={new}", Code: "c={wrong}"}[p]
		e, err := ParsePage(p, "http://localhost:3000/p?x=1", body, tu)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	notLimited := Result{Requests: 20, Baseline: 200, Accepted: 20}
	for _, c := range []struct {
		p    Page
		r    Result
		rule string
		sev  findings.Severity
		cwe  string
		text string
	}{
		{Reset, notLimited, "reset-not-limited", findings.Low, "CWE-799", "The answers do not show whether the app sent an email"},
		{SignUp, notLimited, "signup-not-limited", findings.Low, "CWE-799", "up to 20 accounts were made, named siegekit-new-"},
		{Code, Result{Requests: 20, Baseline: 401}, "code-not-limited", findings.Medium, "CWE-307", "20 wrong codes"},
		{Code, Result{Requests: 1, Limited: true, Signal: "answered with a X-Ratelimit-Limit header, already at the first request", Limit: 100}, "code-limit-high", findings.Low, "CWE-307", "allows 100 requests per window, more than 10"},
		{Code, Result{Requests: 16, Limited: true, Signal: "answered 429"}, "code-limit-high", findings.Low, "CWE-307", "it took 15 wrong codes before it answered 429"},
	} {
		fs := Findings(mk(c.p), c.r, 20)
		if len(fs) != 1 || fs[0].RuleID != c.rule || fs[0].Severity != c.sev || fs[0].CWEs[0] != c.cwe || fs[0].Location.URI != "http://localhost:3000/p" ||
			fs[0].Sources[0].Plugin != c.p.ID() || fs[0].Fingerprint == "" || !strings.Contains(fs[0].Message, c.text) {
			t.Errorf("%s %+v: %+v", c.p, c.r, fs)
		}
	}
	for _, c := range []struct {
		p Page
		r Result
	}{
		{Code, Result{Requests: 3, Limited: true, Signal: "answered 429"}},
		{Code, Result{Requests: 1, Limited: true, Signal: "x", Limit: 10}},
		{Code, Result{Requests: 1, Limited: true, Signal: "answered 429, already at the first request"}},
		{Reset, Result{Requests: 1, Limited: true, Limit: 100}},
		{Reset, Result{Requests: 19, Baseline: 200}},
		{SignUp, Result{Requests: 20, Baseline: 201, Changed: 1}},
	} {
		if fs := Findings(mk(c.p), c.r, 20); len(fs) != 0 {
			t.Errorf("%s %+v: %+v", c.p, c.r, fs)
		}
	}
}

// FuzzPagesFromHAR: any recorded body gives a page whose filled-in bodies
// are valid JSON or forms, that never carry the recorded value of a field
// SiegeKit fills in, and with no placeholder left.
func FuzzPagesFromHAR(f *testing.F) {
	for _, s := range [][2]string{
		{"/rest/user/reset-password", `{"email":"a@b.test","answer":"blue","new":"x"}`},
		{"/user/forgot_password", "_csrf=t&email=a%40b.test"},
		{"/user/sign_up", "user_name=a&email=a%40b.test&password=p"},
		{"/api/Users/", `{"email":"a@b.test","password":"p","passwordRepeat":"p"}`},
		{"/rest/2fa/verify", `{"tmpToken":"t","totpToken":123456}`},
		{"/user/two_factor", "passcode=1&x=%7Bwrong%7D"},
	} {
		f.Add(s[0], s[1])
	}
	tu := mustTarget(f, "http://localhost:3000/")
	f.Fuzz(func(t *testing.T, path, body string) {
		mime := formMIME
		if startsJSON(body) {
			mime = jsonMIME
		}
		h, err := PagesFromHAR(har([4]string{"POST", "http://localhost:3000" + path, mime, body}), tu, "a.har")
		if err != nil {
			return
		}
		for p, e := range h.Pages {
			b := string(e.next())
			if strings.Contains(b, wrongPH) || strings.Contains(b, newPH) {
				t.Fatalf("%s: placeholder left in %q", p, b)
			}
			if e.json && !json.Valid([]byte(b)) {
				t.Fatalf("%s: invalid JSON %q from %q", p, b, body)
			}
			if !e.json {
				if _, err := url.ParseQuery(b); err != nil {
					t.Fatalf("%s: invalid form %q from %q: %v", p, b, body, err)
				}
			}
			// A code page never sends the recorded body: its code is
			// always replaced.
			if p == Code && b == body {
				t.Fatalf("code sent as recorded: %q", b)
			}
		}
	})
}
