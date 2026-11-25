package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/webform"
)

// A reset or sign-up page whose form only a browser can send (a Next.js
// Server Action, a CSRF token) is given as the page itself (ADR 0069):
// before each request SiegeKit reads the page and sends its form, as the
// login checks do with --login-page (ADR 0062).

// htmlAccept is the Accept header of the requests a browser makes for a
// page.
const htmlAccept = "text/html,application/xhtml+xml"

// PageFlag is the page's page flag, such as --signup-page, "" for a page
// that has none (the code page).
func (p Page) PageFlag() string {
	if p == Code {
		return ""
	}
	return "--" + string(p) + "-page"
}

// ParsePageForm checks a page's --<page>-page and --<page>-body values
// (ADR 0069). The page must be on the target's origin and may have a
// query. The body names the form's fields as a form body, such as
// "email={new}@example.com&password=...", with the placeholders of
// ParsePage in values only: SiegeKit fills them in and sends the page's
// form with its other fields as the page has them.
func ParsePageForm(p Page, rawPage, body string, t *target.URL) (*Endpoint, error) {
	flag, bodyFlag := p.PageFlag(), "--"+string(p)+"-body"
	if flag == "" {
		return nil, fmt.Errorf("the %s has no page flag", p.What())
	}
	u, query, err := target.OnOrigin(t, rawPage, flag, true)
	if err != nil {
		return nil, err
	}
	if err := checkTemplate(p, flag, body); err != nil {
		return nil, err
	}
	if startsJSON(body) {
		ex := "email=you%40example.com"
		if p == SignUp {
			ex = "email={new}%40example.com&password=..."
		}
		return nil, fmt.Errorf("with %s, %s names the form's fields as a form body, such as '%s'", flag, bodyFlag, ex)
	}
	e := &Endpoint{URL: u.String(), Path: u.Path, Method: http.MethodPost, Page: p, From: flag, Form: true, body: []byte(body), target: t}
	if query != "" {
		e.URL += "?" + query
		e.Path += "?" + query
	}
	if e.pageURL, err = url.Parse(e.URL); err != nil {
		return nil, fmt.Errorf("%s: %v", flag, err)
	}
	if e.fields, err = webform.ParseFields(body, bodyFlag, wrongPH, newPH); err != nil {
		return nil, err
	}
	return e, nil
}

// shot is what one request of a reset, sign-up or code check got.
type shot struct {
	page    *egress.Answer // a form's page, read first; nil for a body sent as is
	words   []string       // the page's limit words
	formErr error          // why the page's form could not be sent
	form    *webform.Submission
	a       *egress.Answer // the answer; nil when the form was not sent
	// next is the page a reset's or sign-up's 301, 302 or 303 named, read
	// as a browser does, and nextWords its limit words (ADR 0069); nil
	// when the answer was not such a redirect.
	next      *egress.Answer
	nextWords []string
}

// try sends one request with wrong and name as the values of {wrong} and
// {new}. With a page flag it first reads the page, with no cookie, then
// sends its form with the cookies the page set and the target's Origin,
// as a browser with no JavaScript does. A reset's or sign-up's redirect
// is followed once. r counts the page reads and redirects followed. An
// answer longer than MaxAnswer still counts, as before.
func (e *Endpoint) try(ctx context.Context, cfg egress.Config, wrong, name string, r *Result) (*shot, error) {
	s := &shot{}
	method, path, h, body, from, sent := e.Method, e.Path, http.Header{}, e.bodyFor(wrong, name), e.URL, ""
	if ct := e.ContentType(); ct != "" {
		h.Set("Content-Type", ct)
	}
	if e.Form {
		pa, err := send(ctx, cfg, http.MethodGet, e.Path, http.Header{"Accept": {htmlAccept}}, nil, MaxAnswer)
		if err != nil {
			return nil, err
		}
		r.Reads++
		s.page, s.words = pa, LimitWords(pa.Body)
		if pa.Status != http.StatusOK {
			return s, nil
		}
		if s.form, s.formErr = webform.Read(pa.Body).Build(e.pageURL, e.target, e.fields, strings.NewReplacer(wrongPH, wrong, newPH, name)); s.formErr != nil {
			return s, nil
		}
		method, path, body, from = http.MethodPost, s.form.Path, s.form.Body, s.form.URL
		h = http.Header{"Content-Type": {s.form.ContentType}, "Origin": {e.target.Origin()}, "Accept": {htmlAccept}}
		if sent = webform.Cookies(pa.Header, e.target.Host, e.pageURL.Path, path, now()); sent != "" {
			h.Set("Cookie", sent)
		}
	}
	a, err := send(ctx, cfg, method, path, h, body, MaxAnswer)
	if a == nil || err != nil && !errors.Is(err, egress.ErrTooLarge) {
		return nil, err
	}
	s.a = a
	if e.Page != Reset && e.Page != SignUp {
		return s, nil
	}
	next, cookie, ok := webform.Next(e.target, a, from, path, sent, now())
	if !ok {
		return s, nil
	}
	nh := http.Header{"Accept": {htmlAccept}}
	if cookie != "" {
		nh.Set("Cookie", cookie)
	}
	if s.next, err = send(ctx, cfg, http.MethodGet, next, nh, nil, MaxAnswer); s.next == nil || err != nil && !errors.Is(err, egress.ErrTooLarge) {
		return nil, err
	}
	r.Reads++
	s.nextWords = LimitWords(s.next.Body)
	return s, nil
}

// own puts {new} and {wrong} back for the values a request held, so a
// redirect that names the account it made (/users/siegekit-new-…) reads
// the same each time.
func own(wrong, name string) *strings.Replacer {
	return strings.NewReplacer(name, newPH, wrong, wrongPH)
}

// location is a reset's or sign-up's redirect with the request's own
// values and random values left out (ADR 0062 item 4), "" for an answer
// that is not a redirect: a 201's Location names the account it made
// (Juice Shop's /api/Users/27), not where a browser goes (measured, ADR
// 0069).
func location(a *egress.Answer, values *strings.Replacer) string {
	if a.Status < 300 || a.Status > 399 {
		return ""
	}
	return webform.Strip(values.Replace(a.Header.Get("Location")))
}

func orNone(s string) string {
	if s == "" {
		return "no redirect"
	}
	return s
}

// formBody is a form page's filled-in fields as a form body, for finding
// the email addresses a request held.
func (e *Endpoint) formBody(wrong, name string) []byte {
	fill := strings.NewReplacer(wrongPH, wrong, newPH, name)
	v := make([]string, len(e.fields))
	for i, f := range e.fields {
		v[i] = url.QueryEscape(f.Name) + "=" + url.QueryEscape(fill.Replace(f.Value))
	}
	return []byte(strings.Join(v, "&"))
}

// differs reports whether an answer's shape differs from the page's own
// answer to a GET (guard G1, ADR 0069): its status, its redirect, or a
// cookie it sets that the page did not. A cookie the page set that the
// answer does not set again is no difference: the form was sent with it,
// so the app need not set it again (Gitea 1.24.6's sign-up page sets
// _csrf and i_like_gitea; its answer to the form, which carries them,
// sets neither, measured).
func differs(a, page webform.Shape) bool {
	if a.Status != page.Status || a.Location != page.Location {
		return true
	}
	had := strings.Split(page.Cookies, ",")
	for c := range strings.SplitSeq(a.Cookies, ",") {
		if c != "" && !slices.Contains(had, c) {
			return true
		}
	}
	return false
}
