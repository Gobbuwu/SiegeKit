package login

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/htmltag"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// A login page's form is read the way a browser without JavaScript sends
// it (ADR 0062): the HTML standard's form submission, cut down to what
// login forms use. ASP.NET's __VIEWSTATE can be tens of KiB, so values are
// kept up to the size of a whole answer.
const maxValue = MaxAnswer

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

// page is what readPage found.
type page struct {
	base  string // the first <base href>, "" for none
	forms []*form
	words []string
}

// rawText are elements whose content is text, not tags.
var rawText = []string{"script", "style", "title", "textarea", "xmp", "noembed", "noframes", "template", "iframe"}

// readPage reads a page's forms. Like a browser's parser, it ignores a
// <form> inside another, and a control belongs to the form that its form
// attribute names, or else to the form it is in.
func readPage(b []byte) *page {
	lower := htmltag.Lower(b)
	pg := &page{}
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
	pg.words = ratelimit.LimitWords(b)
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

// field is one name and value of a login body template.
type field struct{ name, value string }

// formLogin is the request a login page's form makes.
type formLogin struct {
	path        string // path and query on the target's origin
	url         string // for reports
	contentType string
	body        []byte
	button      string // the submit button's label, for reports
}

// describe says how the form was sent, for reports.
func (f *formLogin) describe() string {
	ct, _, _ := strings.Cut(f.contentType, ";")
	if f.button == "" {
		return ct + ", no submit button"
	}
	return fmt.Sprintf("%s, button %q", ct, f.button)
}

// ErrNoForm is the error for a page with no login form SiegeKit can send.
var ErrNoForm = errors.New("no login form")

// build fills in the login page's form for user and password, as a
// browser does when the person presses Enter in it: the form is the first
// one with every field the template names, the button is its first submit
// button (the form's default button), hidden fields keep their values,
// and the template's fields are set. pageURL is the page's URL, t the
// target.
func (pg *page) build(pageURL *url.URL, t *target.URL, tmpl []field, user, password string) (*formLogin, error) {
	var f *form
	for _, cand := range pg.forms {
		ok := true
		for _, tf := range tmpl {
			ok = ok && cand.field(tf.name) != nil
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
		return nil, fmt.Errorf("%w: the login form is sent with %s, and the login checks send POST requests", ErrNoForm, strings.ToUpper(m))
	}
	enc, _ := attr("formenctype", "enctype")
	ct := "application/x-www-form-urlencoded"
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "multipart/form-data":
		ct = "multipart/form-data"
	case "text/plain":
		return nil, fmt.Errorf("%w: the login form is sent as text/plain, which SiegeKit does not send", ErrNoForm)
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
			return nil, fmt.Errorf("%w: the login form's action %q is not a URL: %v", ErrNoForm, action, err)
		}
	}
	if to.Scheme == "javascript" {
		return nil, fmt.Errorf("%w: the login form is sent only by JavaScript (its action is a javascript: URL)", ErrNoForm)
	}
	to.Fragment, to.RawFragment = "", ""
	u, query, err := target.OnOrigin(t, to.String(), "the login form's action", true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoForm, err)
	}
	fl := &formLogin{path: u.Path, url: u.String(), contentType: ct}
	if query != "" {
		fl.path += "?" + query
		fl.url += "?" + query
	}
	if submit != nil {
		fl.button = submit.label
	}
	set := map[*control]string{}
	fill := strings.NewReplacer("{user}", user, "{password}", password)
	for _, tf := range tmpl {
		set[f.field(tf.name)] = fill.Replace(tf.value)
	}
	// The form's data set: controls in document order (HTML standard,
	// constructing the entry list).
	var entries []field
	for _, c := range f.controls {
		v, fromTemplate := set[c]
		switch {
		case fromTemplate:
			entries = append(entries, field{c.name, v})
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
				entries = append(entries, field{p + "x", "0"}, field{p + "y", "0"})
			} else if c.name != "" {
				entries = append(entries, field{c.name, c.value})
			}
		case c.name == "":
		case c.tag == "button", c.typ == "reset", c.typ == "button", c.typ == "file":
		case c.typ == "checkbox" || c.typ == "radio":
			if c.checked {
				if _, ok := c.attrs["value"]; !ok {
					c.value = "on"
				}
				entries = append(entries, field{c.name, c.value})
			}
		case c.tag == "select":
			for _, o := range c.options {
				entries = append(entries, field{c.name, o})
			}
		case c.typ == "hidden" && strings.EqualFold(c.name, "_charset_"):
			entries = append(entries, field{c.name, "UTF-8"})
		default:
			entries = append(entries, field{c.name, c.value})
		}
	}
	if ct == "multipart/form-data" {
		fl.body, fl.contentType = multipartBody(entries)
	} else {
		v := make([]string, len(entries))
		for i, e := range entries {
			v[i] = url.QueryEscape(e.name) + "=" + url.QueryEscape(e.value)
		}
		fl.body = []byte(strings.Join(v, "&"))
	}
	return fl, nil
}

// field returns the form's first control named name that the template can
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
func multipartBody(entries []field) ([]byte, string) {
	boundary := "----SiegeKitFormBoundary" + rand.Text()[:16]
	esc := strings.NewReplacer("\"", "%22", "\r", "%0D", "\n", "%0A")
	var b bytes.Buffer
	for _, e := range entries {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, esc.Replace(e.name), e.value)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), "multipart/form-data; boundary=" + boundary
}

// names lists the template's field names, for errors.
func names(tmpl []field) string {
	q := make([]string, len(tmpl))
	for i, f := range tmpl {
		q[i] = fmt.Sprintf("%q", f.name)
	}
	return strings.Join(q, " and ")
}

// describe says which forms and fields a page has, for errors.
func (pg *page) describe() string {
	if len(pg.forms) == 0 {
		return "it has no <form>; a login built only by JavaScript cannot be sent this way"
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

// cookies returns the Cookie header a browser would send to path after
// receiving the Set-Cookie headers in h from the page at pagePath on host
// (RFC 6265 domain and path matching), or "".
func cookies(h http.Header, host, pagePath, path string, now time.Time) string {
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
