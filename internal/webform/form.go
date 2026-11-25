// Package webform reads the forms of a page and fills one in as a browser
// without JavaScript sends it (ADR 0062), for the login checks and the
// reset and sign-up checks (ADR 0069). It sends nothing itself: the
// checks send the requests it builds, so each counts and paces its own.
package webform

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/htmltag"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// A page's form is read the way a browser without JavaScript sends it
// (ADR 0062): the HTML standard's form submission, cut down to what login,
// reset and sign-up forms use. ASP.NET's __VIEWSTATE can be tens of KiB,
// so values are kept up to the size of a whole answer the checks read.
const maxValue = 2 << 20

// control is a form control: an input, button, select or textarea.
type control struct {
	tag, typ string // typ: the input or button type, in lower case
	name     string
	value    string   // input value, textarea text
	options  []string // select: the values sent (selected, or the first)
	checked  bool
	disabled bool
	attrs    map[string]string
	label    string // a button's text, for reports
	owner    int    // the form it belongs to, -1 for none
}

// form is a <form> with its controls in document order.
type form struct {
	attrs    map[string]string
	controls []*control
}

// Page is what Read found.
type Page struct {
	base  string // the first <base href>, "" for none
	forms []*form
}

// rawText are elements whose content is text, not tags.
var rawText = []string{"script", "style", "title", "textarea", "xmp", "noembed", "noframes", "template", "iframe"}

// Read reads a page's forms. Like a browser's parser, it ignores a
// <form> inside another, and a control belongs to the form that its form
// attribute names, or else to the form it is in.
func Read(b []byte) *Page {
	lower := htmltag.Lower(b)
	pg := &Page{}
	var all []*control
	ids := map[string]int{} // form id -> index, the first of each
	open := -1              // the open form
	var sel *control        // the open select
	for i := 0; i < len(b); {
		j := bytes.IndexByte(b[i:], '<')
		if j < 0 {
			break
		}
		i += j
		switch {
		case bytes.HasPrefix(b[i:], []byte("<!--")):
			k := bytes.Index(b[i+4:], []byte("-->"))
			if k < 0 {
				i = len(b)
				continue
			}
			i += 4 + k + 3
			continue
		case endTag(lower, i, "form"):
			open = -1
			sel = nil
		case endTag(lower, i, "select"):
			sel = nil
		}
		name, attrs, end := htmltag.Read(b, lower, i, maxValue)
		i = end
		switch name {
		case "base":
			if h, ok := attrs["href"]; ok && pg.base == "" {
				pg.base = strings.TrimSpace(h)
			}
		case "form":
			if open < 0 {
				pg.forms = append(pg.forms, &form{attrs: attrs})
				open = len(pg.forms) - 1
				if id, ok := attrs["id"]; ok {
					if _, seen := ids[id]; !seen {
						ids[id] = open
					}
				}
			}
		case "input", "button", "select", "textarea":
			c := &control{tag: name, name: attrs["name"], attrs: attrs, owner: open}
			_, c.disabled = attrs["disabled"]
			_, c.checked = attrs["checked"]
			c.typ = strings.ToLower(strings.TrimSpace(attrs["type"]))
			c.value = attrs["value"]
			switch name {
			case "button":
				if c.typ != "reset" && c.typ != "button" {
					c.typ = "submit" // missing or invalid: a submit button
				}
				c.label = text(b, lower, i, "button")
			case "input":
				if c.typ == "" {
					c.typ = "text"
				}
				if c.typ == "submit" || c.typ == "image" {
					c.label = strings.TrimSpace(attrs["value"])
				}
			case "select":
				sel = c
				_, multiple := attrs["multiple"]
				c.typ = "select"
				if multiple {
					c.typ = "select-multiple"
				}
			case "textarea":
				t := rawContent(b, lower, i, "textarea")
				// The parser drops one newline right after the tag.
				t = strings.TrimPrefix(strings.TrimPrefix(t, "\r"), "\n")
				c.value = html.UnescapeString(t)
			}
			all = append(all, c)
		case "option":
			if sel == nil {
				break
			}
			if _, d := attrs["disabled"]; d {
				break
			}
			v, ok := attrs["value"]
			if !ok {
				v = strings.Join(strings.Fields(html.UnescapeString(textUntilTag(b, i))), " ")
			}
			_, s := attrs["selected"]
			switch {
			case s && sel.typ == "select": // the last selected option wins
				sel.options, sel.checked = []string{v}, true
			case s:
				sel.options = append(sel.options, v)
			case sel.typ == "select" && !sel.checked && len(sel.options) == 0:
				sel.options = []string{v} // the first option, until one is selected
			}
		}
		for _, r := range rawText {
			if name == r {
				if k := bytes.Index(lower[i:], []byte("</"+r)); k >= 0 {
					i += k
				} else {
					i = len(b)
				}
			}
		}
	}
	for _, c := range all {
		if f, ok := c.attrs["form"]; ok {
			c.owner = -1
			if k, ok := ids[f]; ok {
				c.owner = k
			}
		}
		if c.owner >= 0 {
			pg.forms[c.owner].controls = append(pg.forms[c.owner].controls, c)
		}
	}
	return pg
}

// endTag reports whether lower has the end tag </name at i.
func endTag(lower []byte, i int, name string) bool {
	t := lower[i:]
	if !bytes.HasPrefix(t, []byte("</"+name)) {
		return false
	}
	return len(t) == len(name)+2 || htmltag.IsSpace(t[len(name)+2]) || t[len(name)+2] == '>' || t[len(name)+2] == '/'
}

// rawContent is the text from i to the end tag </name.
func rawContent(b, lower []byte, i int, name string) string {
	k := bytes.Index(lower[i:], []byte("</"+name))
	if k < 0 {
		k = len(b) - i
	}
	return string(b[i : i+k])
}

// text is the content from i to </name with tags left out, entities
// decoded and white space collapsed, at most 60 bytes: a button's label.
func text(b, lower []byte, i int, name string) string {
	raw := rawContent(b, lower, i, name)
	var sb strings.Builder
	in := false
	for _, r := range raw {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			sb.WriteRune(r)
		}
	}
	s := strings.Join(strings.Fields(html.UnescapeString(sb.String())), " ")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// textUntilTag is the text from i to the next tag.
func textUntilTag(b []byte, i int) string {
	k := bytes.IndexByte(b[i:], '<')
	if k < 0 {
		k = len(b) - i
	}
	return string(b[i : i+k])
}

// Field is one name and value of a body template, such as a login's
// "email={user}".
type Field struct{ Name, Value string }

// Submission is the request a page's form makes.
type Submission struct {
	Path        string // path and query on the target's origin
	URL         string // for reports
	ContentType string
	Body        []byte
	Button      string // the submit button's label, for reports
}

// Describe says how the form was sent, for reports.
func (f *Submission) Describe() string {
	ct, _, _ := strings.Cut(f.ContentType, ";")
	if f.Button == "" {
		return ct + ", no submit button"
	}
	return fmt.Sprintf("%s, button %q", ct, f.Button)
}

// ErrNoForm is the error for a page with no form SiegeKit can send.
var ErrNoForm = errors.New("no form SiegeKit can send")

// Build fills in the page's form as a browser does when the person
// presses Enter in it: the form is the first one with every field the
// template names, the button is its first submit button (the form's
// default button), hidden fields keep their values, and the template's
// fields are set, with fill applied to their values (nil: as they are).
// pageURL is the page's URL, t the target.
func (pg *Page) Build(pageURL *url.URL, t *target.URL, tmpl []Field, fill *strings.Replacer) (*Submission, error) {
	var f *form
	for _, cand := range pg.forms {
		ok := true
		for _, tf := range tmpl {
			ok = ok && cand.field(tf.Name) != nil
		}
		if ok {
			f = cand
			break
		}
	}
	if f == nil {
		return nil, fmt.Errorf("%w: the page has no form with the fields %s (%s)", ErrNoForm, names(tmpl), pg.describe())
	}
	var submit *control
	for _, c := range f.controls {
		if c.isSubmit() {
			submit = c
			break
		}
	}
	if submit != nil && submit.disabled {
		return nil, fmt.Errorf("%w: the form's first submit button %q is disabled; perhaps JavaScript enables it", ErrNoForm, submit.label)
	}
	// The submit button's formaction, formmethod and formenctype win
	// over the form's own (HTML standard, form submission).
	attr := func(button, form string) (string, bool) {
		if submit != nil {
			if v, ok := submit.attrs[button]; ok {
				return v, true
			}
		}
		v, ok := f.attrs[form]
		return v, ok
	}
	method, _ := attr("formmethod", "method")
	if m := strings.ToLower(strings.TrimSpace(method)); m != "post" {
		if m != "dialog" {
			m = "get" // missing or invalid: GET
		}
		return nil, fmt.Errorf("%w: the form is sent with %s, and these checks send POST requests", ErrNoForm, strings.ToUpper(m))
	}
	enc, _ := attr("formenctype", "enctype")
	ct := "application/x-www-form-urlencoded"
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "multipart/form-data":
		ct = "multipart/form-data"
	case "text/plain":
		return nil, fmt.Errorf("%w: the form is sent as text/plain, which SiegeKit does not send", ErrNoForm)
	}
	// The action, resolved like a browser does: against <base href>, then
	// the page; an empty action is the page itself.
	base := pageURL
	if pg.base != "" {
		if b, err := pageURL.Parse(pg.base); err == nil {
			base = b
		}
	}
	action, _ := attr("formaction", "action")
	action = strings.TrimSpace(action)
	var to *url.URL
	if action == "" {
		to = pageURL
	} else {
		var err error
		if to, err = base.Parse(action); err != nil {
			return nil, fmt.Errorf("%w: the form's action %q is not a URL: %v", ErrNoForm, action, err)
		}
	}
	if to.Scheme == "javascript" {
		return nil, fmt.Errorf("%w: the form is sent only by JavaScript (its action is a javascript: URL)", ErrNoForm)
	}
	to.Fragment, to.RawFragment = "", ""
	u, query, err := target.OnOrigin(t, to.String(), "the form's action", true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoForm, err)
	}
	fl := &Submission{Path: u.Path, URL: u.String(), ContentType: ct}
	if query != "" {
		fl.Path += "?" + query
		fl.URL += "?" + query
	}
	if submit != nil {
		fl.Button = submit.label
	}
	set := map[*control]string{}
	for _, tf := range tmpl {
		v := tf.Value
		if fill != nil {
			v = fill.Replace(v)
		}
		set[f.field(tf.Name)] = v
	}
	// The form's data set: controls in document order (HTML standard,
	// constructing the entry list).
	var entries []Field
	for _, c := range f.controls {
		v, fromTemplate := set[c]
		switch {
		case fromTemplate:
			entries = append(entries, Field{c.name, v})
		case c.disabled:
		case c.isSubmit():
			if c != submit {
				continue
			}
			if c.typ == "image" {
				p := ""
				if c.name != "" {
					p = c.name + "."
				}
				entries = append(entries, Field{p + "x", "0"}, Field{p + "y", "0"})
			} else if c.name != "" {
				entries = append(entries, Field{c.name, c.value})
			}
		case c.name == "":
		case c.tag == "button", c.typ == "reset", c.typ == "button", c.typ == "file":
		case c.typ == "checkbox" || c.typ == "radio":
			if c.checked {
				if _, ok := c.attrs["value"]; !ok {
					c.value = "on"
				}
				entries = append(entries, Field{c.name, c.value})
			}
		case c.tag == "select":
			for _, o := range c.options {
				entries = append(entries, Field{c.name, o})
			}
		case c.typ == "hidden" && strings.EqualFold(c.name, "_charset_"):
			entries = append(entries, Field{c.name, "UTF-8"})
		default:
			entries = append(entries, Field{c.name, c.value})
		}
	}
	if ct == "multipart/form-data" {
		fl.Body, fl.ContentType = multipartBody(entries)
	} else {
		v := make([]string, len(entries))
		for i, e := range entries {
			v[i] = url.QueryEscape(e.Name) + "=" + url.QueryEscape(e.Value)
		}
		fl.Body = []byte(strings.Join(v, "&"))
	}
	return fl, nil
}

// field returns the form's first control named name that a template can
// fill: not a button, reset or file input.
func (f *form) field(name string) *control {
	for _, c := range f.controls {
		if c.name == name && c.tag != "button" && !c.isSubmit() && c.typ != "reset" && c.typ != "button" && c.typ != "file" {
			return c
		}
	}
	return nil
}

// isSubmit reports whether c is a submit button.
func (c *control) isSubmit() bool {
	return c.tag == "button" && c.typ == "submit" || c.tag == "input" && (c.typ == "submit" || c.typ == "image")
}

// multipartBody encodes entries as multipart/form-data, as browsers do:
// names with '"', CR or LF percent-encoded (HTML standard).
func multipartBody(entries []Field) ([]byte, string) {
	boundary := "----SiegeKitFormBoundary" + rand.Text()[:16]
	esc := strings.NewReplacer("\"", "%22", "\r", "%0D", "\n", "%0A")
	var b bytes.Buffer
	for _, e := range entries {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, esc.Replace(e.Name), e.Value)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), "multipart/form-data; boundary=" + boundary
}

// names lists the template's field names, for errors.
func names(tmpl []Field) string {
	q := make([]string, len(tmpl))
	for i, f := range tmpl {
		q[i] = fmt.Sprintf("%q", f.Name)
	}
	return strings.Join(q, " and ")
}

// describe says which forms and fields a page has, for errors.
func (pg *Page) describe() string {
	if len(pg.forms) == 0 {
		return "it has no <form>; a form built only by JavaScript cannot be sent this way"
	}
	var parts []string
	for i, f := range pg.forms {
		var ns []string
		for _, c := range f.controls {
			if c.name != "" && !c.isSubmit() && c.typ != "hidden" {
				ns = append(ns, c.name)
			}
		}
		parts = append(parts, fmt.Sprintf("form %d has %s", i+1, strings.Join(ns, ", ")))
		if i == 4 {
			parts = append(parts, fmt.Sprintf("%d more", len(pg.forms)-5))
			break
		}
	}
	return strings.Join(parts, "; ")
}

// Cookies returns the Cookie header a browser would send to path after
// receiving the Set-Cookie headers in h from the page at pagePath on host
// (RFC 6265 domain and path matching), or "".
func Cookies(h http.Header, host, pagePath, path string, now time.Time) string {
	var out []string
	seen := map[string]int{}
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == "" || c.MaxAge < 0 || !c.Expires.IsZero() && c.Expires.Before(now) {
			continue
		}
		if d := strings.TrimPrefix(strings.ToLower(c.Domain), "."); d != "" && host != d && !strings.HasSuffix(host, "."+d) {
			continue
		}
		cp := c.Path
		if !strings.HasPrefix(cp, "/") { // the default path: the page's directory
			cp = "/"
			if k := strings.LastIndex(pagePath, "/"); k > 0 {
				cp = pagePath[:k]
			}
		}
		if path != cp && !(strings.HasPrefix(path, cp) && (strings.HasSuffix(cp, "/") || path[len(cp)] == '/' || path[len(cp)] == '?')) {
			continue
		}
		kv := c.Name + "=" + c.Value
		if k, ok := seen[c.Name]; ok {
			out[k] = kv // a later Set-Cookie for the same name wins
			continue
		}
		seen[c.Name] = len(out)
		out = append(out, kv)
	}
	return strings.Join(out, "; ")
}

// MergeCookies joins two Cookie headers; a cookie in set replaces one of
// the same name in sent, as a browser keeps the newer value.
func MergeCookies(sent, set string) string {
	var out []string
	names := map[string]int{}
	for _, h := range []string{sent, set} {
		for kv := range strings.SplitSeq(h, "; ") {
			if kv == "" {
				continue
			}
			name, _, _ := strings.Cut(kv, "=")
			if k, ok := names[name]; ok {
				out[k] = kv
				continue
			}
			names[name] = len(out)
			out = append(out, kv)
		}
	}
	return strings.Join(out, "; ")
}

// Next is the request a browser makes after an answer to a form it sent
// to from (fromPath on the target's origin) with the Cookie header sent:
// for a 301, 302 or 303 to a URL on the target's origin, a GET of that
// path and query with the cookies sent and those the answer set (ADR 0062
// item 4). ok is false when there is none: another status (a 307 or 308
// would send the form again), no Location, or a URL elsewhere, since
// SiegeKit sends requests only to the target.
func Next(t *target.URL, a *egress.Answer, from, fromPath, sent string, now time.Time) (path, cookie string, ok bool) {
	loc := a.Header.Get("Location")
	if t == nil || loc == "" || a.Status != http.StatusMovedPermanently && a.Status != http.StatusFound && a.Status != http.StatusSeeOther {
		return "", "", false
	}
	base, err := url.Parse(from)
	if err != nil {
		return "", "", false
	}
	to, err := base.Parse(loc)
	if err != nil {
		return "", "", false
	}
	to.Fragment, to.RawFragment = "", ""
	u, query, err := target.OnOrigin(t, to.String(), "the redirect", true)
	if err != nil {
		return "", "", false
	}
	path = u.Path
	if query != "" {
		path += "?" + query
	}
	return path, MergeCookies(sent, Cookies(a.Header, t.Host, fromPath, path, now)), true
}

// Shape is what tells a form's answers apart (ADR 0062, ADR 0069): the
// status, the redirect, and the names of the cookies it sets. A body is
// not compared: two answers to the same ignored form differ byte for byte
// (measured on Next.js 16).
type Shape struct {
	Status   int
	Location string // the redirect with random values left out (Strip)
	Cookies  string // the names of the cookies set, sorted, joined by ","
}

// ShapeOf is an answer's shape with loc as its redirect, which the caller
// gives with random values left out (Redirect).
func ShapeOf(a *egress.Answer, loc string) Shape {
	var names []string
	for _, c := range (&http.Response{Header: a.Header}).Cookies() {
		if c.MaxAge >= 0 && !slices.Contains(names, c.Name) {
			names = append(names, c.Name)
		}
	}
	slices.Sort(names)
	return Shape{a.Status, loc, strings.Join(names, ",")}
}

func (s Shape) String() string {
	out := fmt.Sprintf("answered %d", s.Status)
	if s.Location != "" {
		out += " to " + s.Location
	}
	if s.Cookies != "" {
		out += " setting the cookies " + s.Cookies
	}
	return out
}

// token is a run of letters, digits and hyphens.
var token = regexp.MustCompile(`[A-Za-z0-9-]+`)

// Redirect is an answer's Location with random values left out (Strip).
func Redirect(a *egress.Answer) string { return Strip(a.Header.Get("Location")) }

// Strip leaves random values out of a URL: a run of letters, digits and
// hyphens 8 or more long with a digit (a token, an ID or a time) becomes
// "*" (ADR 0062). Words such as "over_request_rate_limit" stay.
func Strip(loc string) string {
	if len(loc) > 2048 {
		loc = loc[:2048]
	}
	return token.ReplaceAllStringFunc(loc, func(t string) string {
		if len(t) >= 8 && strings.ContainsAny(t, "0123456789") {
			return "*"
		}
		return t
	})
}

// ParseFields reads a body template that names a form's fields, such as
// "email={user}&password={password}": each field once, with a name, as a
// form body, with the placeholders in values only. flag names the body's
// flag in errors.
func ParseFields(body, flag string, placeholders ...string) ([]Field, error) {
	var out []Field
	seen := map[string]bool{}
	for kv := range strings.SplitSeq(body, "&") {
		k, v, _ := strings.Cut(kv, "=")
		name, err1 := url.QueryUnescape(k)
		value, err2 := url.QueryUnescape(v)
		switch {
		case err1 != nil || err2 != nil:
			return nil, fmt.Errorf("%s is not a valid form body: %v", flag, errors.Join(err1, err2))
		case name == "":
			return nil, fmt.Errorf("%s has a field with no name", flag)
		case slices.ContainsFunc(placeholders, func(p string) bool { return strings.Contains(name, p) }):
			return nil, fmt.Errorf("%s has %s in a field name; they go in values, such as '%s'", flag, strings.Join(placeholders, " or "), example(placeholders))
		case seen[name]:
			return nil, fmt.Errorf("%s names the field %q twice", flag, name)
		}
		seen[name] = true
		out = append(out, Field{name, value})
	}
	return out, nil
}

// example is a field with the first placeholder, for errors.
func example(placeholders []string) string {
	if len(placeholders) == 0 {
		return "name=value"
	}
	return "email=" + placeholders[0]
}
