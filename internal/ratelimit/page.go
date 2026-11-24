package ratelimit

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/mailcatcher"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// Page is a kind of page whose requests the reset, sign-up and code checks
// repeat (ADR 0055): each is today's rate-limit check on one page, with
// its own check ID, so each has its own line in the report.
type Page string

// The pages, in the order they run.
const (
	Reset  Page = "reset"
	SignUp Page = "signup"
	Code   Page = "code"
)

// Pages lists every page kind, in the order they run.
var Pages = []Page{Reset, SignUp, Code}

// Check IDs and names of the page checks.
const (
	ResetID  = "reset-limit"
	SignUpID = "signup-limit"
	CodeID   = "code-limit"
)

// ID is the page's check ID.
func (p Page) ID() string {
	switch p {
	case Reset:
		return ResetID
	case SignUp:
		return SignUpID
	}
	return CodeID
}

// Name is the page's check name.
func (p Page) Name() string {
	switch p {
	case Reset:
		return "Password-reset limit check"
	case SignUp:
		return "Sign-up limit check"
	}
	return "Verification-code limit check"
}

// Flag is the page's URL flag; its body flag ends in -body.
func (p Page) Flag() string { return "--" + string(p) + "-url" }

// What names the page in plans and reports.
func (p Page) What() string {
	switch p {
	case Reset:
		return "password-reset page"
	case SignUp:
		return "sign-up page"
	}
	return "verification-code page (second factor)"
}

// Placeholders filled in anew for each request: {wrong} with a guess that
// cannot be right (a reset answer, a code), {new} with a user name no
// account has (ADR 0055 item 3).
const (
	wrongPH = "{wrong}"
	newPH   = "{new}"
)

// NISTMaxFailures is the most failed attempts in a row that NIST SP
// 800-63B-4 section 3.2.2 allows before an authenticator is disabled ("no
// more than 100"). A code page that allows more wrong codes a day gets
// code-limit-high (ADR 0055 item 5, owner 2026-11-23).
const NISTMaxFailures = 100

// newDomain is the domain of the email addresses SiegeKit invents for a
// recorded sign-up: example.com is reserved (RFC 2606) and accepts no mail
// (its MX is null, RFC 7505), so no stranger gets an email.
const newDomain = "example.com"

// ParsePage checks a page's --<page>-url and --<page>-body values. The URL
// must be on the target's origin, like --rate-limit-url. The body is
// required and sent as a POST, JSON when it starts with "{" or "[": a
// reset body may hold {wrong} (the answer or code, filled with a wrong
// guess), a code body must hold {wrong}, and a sign-up body must hold
// {new} (filled with a new user name, so each request makes a new
// account).
func ParsePage(p Page, rawURL, body string, t *target.URL) (*Endpoint, error) {
	flag, bodyFlag := p.Flag(), "--"+string(p)+"-body"
	u, query, err := target.OnOrigin(t, rawURL, flag, true)
	if err != nil {
		return nil, err
	}
	switch {
	case body == "":
		return nil, fmt.Errorf("%s needs %s", flag, bodyFlag)
	case len(body) > maxBody:
		return nil, fmt.Errorf("%s is longer than %d bytes", bodyFlag, maxBody)
	case p == Code && !strings.Contains(body, wrongPH):
		return nil, fmt.Errorf(`%s must contain {wrong} where the code goes, for example '{"code":"{wrong}"}'`, bodyFlag)
	case p == SignUp && !strings.Contains(body, newPH):
		return nil, fmt.Errorf(`%s must contain {new} in the user name or email address, for example '{"email":"{new}@example.com","password":"..."}', so each request makes a new account`, bodyFlag)
	case p != SignUp && strings.Contains(body, newPH):
		return nil, fmt.Errorf("%s may contain {wrong} but not {new}", bodyFlag)
	case p == SignUp && strings.Contains(body, wrongPH):
		return nil, fmt.Errorf("%s may contain {new} but not {wrong}", bodyFlag)
	}
	e := &Endpoint{URL: u.String(), Path: u.Path, Method: http.MethodPost, Page: p, From: flag, body: []byte(body)}
	if query != "" {
		e.URL += "?" + query
		e.Path += "?" + query
	}
	e.json = startsJSON(body)
	b := e.render("x", "x")
	if e.json && !json.Valid(b) {
		return nil, fmt.Errorf("%s is not valid JSON once {wrong} and {new} are filled in; put them inside quotes", bodyFlag)
	}
	if !e.json {
		if _, err := url.ParseQuery(string(b)); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON or a valid form body: %v", bodyFlag, err)
		}
	}
	return e, nil
}

func startsJSON(body string) bool {
	t := strings.TrimLeft(body, " \t\r\n")
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

// source names what the person gave for this endpoint, for error messages.
func (e *Endpoint) source() string {
	switch {
	case e.Page == "":
		return "--rate-limit-url and --rate-limit-body"
	case strings.HasPrefix(e.From, "--"):
		return e.From + " and --" + string(e.Page) + "-body"
	}
	return fmt.Sprintf("the %s request recorded in %s, or give %s and --%s-body", e.Page.What(), e.From, e.Page.Flag(), e.Page)
}

// next is the body of the next request: as given for --rate-limit-url,
// with {wrong} and {new} filled in anew for a page.
func (e *Endpoint) next() []byte {
	if e.Page == "" || e.body == nil {
		return e.body
	}
	return e.render(wrongGuess(), newName())
}

// render fills in the placeholders, escaped for JSON strings or forms.
func (e *Endpoint) render(wrong, name string) []byte {
	esc := url.QueryEscape
	if e.json {
		esc = func(s string) string {
			b, _ := json.Marshal(s) // a string always marshals
			return string(b[1 : len(b)-1])
		}
	}
	return []byte(strings.NewReplacer(wrongPH, esc(wrong), newPH, esc(name)).Replace(string(e.body)))
}

// wrongGuess returns a new random value that cannot be a reset answer or a
// code; the prefix shows where it came from in the app's logs.
func wrongGuess() string { return "siegekit-wrong-" + strings.ToLower(rand.Text()[:20]) }

// newName returns a user name no account has; the prefix shows which
// accounts SiegeKit made, so the person can delete them.
func newName() string { return "siegekit-new-" + strings.ToLower(rand.Text()[:12]) }

// LimitNumber reads the number of requests a RateLimit-Limit or
// X-RateLimit-Limit header allows, 0 when there is none (design Q3). Only
// the first number counts ("100" or "100, 100;w=60").
func LimitNumber(h http.Header) int {
	for _, k := range []string{"Ratelimit-Limit", "X-Ratelimit-Limit"} {
		v := strings.TrimSpace(h.Get(k))
		if i := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			v = v[:i]
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// Window reads how long a limit lasts from an answer's headers, 0 when
// they do not say: the w of RateLimit-Policy ("100;w=300"), the reset of
// RateLimit-Reset or of a RateLimit header ("limit=100, reset=50"),
// X-RateLimit-Reset (seconds, or a Unix time when above 10^9, as
// express-rate-limit sends it), or Retry-After (seconds or a date). A reset
// time is the window when the first request starts it, as with
// express-rate-limit (Juice Shop: 300 s, measured 2026-11-23), and shorter
// otherwise. Unix times and dates count from the answer's Date header, or
// from now.
func Window(h http.Header, now time.Time) time.Duration {
	if d, err := http.ParseTime(h.Get("Date")); err == nil {
		now = d
	}
	param := func(v, name string) string {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }) {
			k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.EqualFold(k, name) {
				return val
			}
		}
		return ""
	}
	secs := func(v string) int64 {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return n
	}
	dur := func(n int64) time.Duration {
		if n <= 0 || n > 366*24*3600 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if n := secs(param(h.Get("Ratelimit-Policy"), "w")); n > 0 {
		return dur(n)
	}
	if n := secs(h.Get("Ratelimit-Reset")); n > 0 {
		return dur(n)
	}
	if n := secs(param(h.Get("Ratelimit"), "reset")); n > 0 {
		return dur(n)
	}
	if n := secs(h.Get("X-Ratelimit-Reset")); n > 0 {
		if n > 1e9 {
			n -= now.Unix()
		}
		return dur(n)
	}
	if v := h.Get("Retry-After"); v != "" {
		if n := secs(v); n > 0 {
			return dur(n)
		}
		if t, err := http.ParseTime(v); err == nil {
			return dur(int64(t.Sub(now).Round(time.Second) / time.Second))
		}
	}
	return 0
}

// HARPages are the reset, sign-up and code pages found in a HAR file
// (ADR 0055 item 2).
type HARPages struct {
	Pages map[Page]*Endpoint
	// More counts further pages of each kind the recording had; only the
	// first is tested.
	More map[Page]int
	// Unusable says, for each kind, why a page of that kind found in the
	// recording cannot be tested, when none could.
	Unusable map[Page]string
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method   string `json:"method"`
				URL      string `json:"url"`
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// PagesFromHAR finds the first reset, sign-up and code page among the
// recording's POST requests to the target's origin, and makes each
// body's template: on a reset page every value but the user name, email
// address and CSRF token becomes {wrong}, on a code page the code field
// does, and on a sign-up page the user name and email address become
// {new}. name is the HAR file's name, for reports.
func PagesFromHAR(data []byte, t *target.URL, name string) (HARPages, error) {
	var h harFile
	if err := json.Unmarshal(data, &h); err != nil {
		return HARPages{}, fmt.Errorf("not a HAR file: %v", err)
	}
	out := HARPages{Pages: map[Page]*Endpoint{}, More: map[Page]int{}, Unusable: map[Page]string{}}
	for _, en := range h.Log.Entries {
		r := en.Request
		if r.Method != http.MethodPost || r.PostData == nil {
			continue
		}
		u, query, err := target.OnOrigin(t, r.URL, "--har", true)
		if err != nil {
			continue
		}
		path := u.Path
		if query != "" {
			path += "?" + query
		}
		p := classify(path, r.PostData.MimeType, r.PostData.Text)
		if p == "" {
			continue
		}
		if out.Pages[p] != nil {
			out.More[p]++
			continue
		}
		e := &Endpoint{URL: u.String(), Path: path, Method: http.MethodPost, Page: p, From: name}
		if query != "" {
			e.URL += "?" + query
		}
		body, isJSON, why := template(p, r.PostData.MimeType, r.PostData.Text)
		if why != "" {
			if out.Unusable[p] == "" {
				out.Unusable[p] = fmt.Sprintf("POST %s: %s", e.URL, why)
			}
			continue
		}
		e.body, e.json = body, isJSON
		out.Pages[p] = e
		delete(out.Unusable, p)
	}
	return out, nil
}

// Words that name each page in a path or query (ADR 0055 item 2). A reset
// needs a word that names forgetting or recovery, or "reset" with a word
// for a password, so "/cart/reset" is not one. A code page is named by a
// second-factor word, not "setup", "enroll" or "disable", which change the
// factor rather than check it.
var (
	resetWords    = words("forgot forgotten forgotpassword lostpassword recover recovery recoveraccount resetpassword passwordreset")
	passwordWords = words("password passwords passwd pass pwd")
	signUpWords   = words("signup register registration createaccount")
	codeWords     = words("2fa mfa tfa totp otp twofactor secondfactor")
	notCodeWords  = words("setup enroll enrol enable disable activate deactivate delete remove regenerate recovery")
	loginWords    = words("login signin logon")
	// Body fields.
	codeFields    = words("code otp totp passcode pin otpcode totpcode mfacode authcode verificationcode twofactorcode securitycode onetimecode onetimepassword smscode")
	idFields      = words("email emailaddress mail username user login loginname account accountname name nickname handle phone phonenumber mobile")
	repeatFields  = words("passwordrepeat repeatpassword repeat retype retypepassword passwordconfirm passwordconfirmation confirmpassword password2 passwordagain verifypassword")
	currentFields = words("currentpassword oldpassword")
	// Last path segments that name a collection of users.
	userCollections = words("users user accounts account members customers")
)

// lastSegment is the last non-empty segment of a path, in lower case,
// without its query.
func lastSegment(path string) string {
	path, _, _ = strings.Cut(path, "?")
	segs := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(segs) == 0 {
		return ""
	}
	return strings.ToLower(segs[len(segs)-1])
}

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// tokens splits a path and query into lower-case words, at anything but
// letters and digits and at camelCase, plus each segment and each pair of
// neighbouring words joined ("sign_up" gives "sign", "up" and "signup").
func tokens(s string) []string {
	var out []string
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '?' || r == '&' || r == '=' }) {
		if u, err := url.PathUnescape(seg); err == nil {
			seg = u
		}
		var ws []string
		var cur []rune
		flush := func() {
			if len(cur) > 0 {
				ws = append(ws, strings.ToLower(string(cur)))
				cur = nil
			}
		}
		rs := []rune(seg)
		for i, r := range rs {
			switch {
			case !unicode.IsLetter(r) && !unicode.IsDigit(r):
				flush()
				continue
			case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
				flush()
			}
			cur = append(cur, r)
		}
		flush()
		out = append(out, ws...)
		out = append(out, strings.Join(ws, ""))
		for i := 0; i+1 < len(ws); i++ {
			out = append(out, ws[i]+ws[i+1])
		}
	}
	return out
}

func anyIn(ts []string, set map[string]bool) bool {
	for _, t := range ts {
		if set[t] {
			return true
		}
	}
	return false
}

// norm is a field name in lower case without "-", "_", "." and spaces.
func norm(k string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(strings.ToLower(k))
}

// isCodeField reports whether a field holds a one-time code: a name of
// codeFields, one that ends in "code", or one that starts with a
// second-factor word ("totpToken", Juice Shop's).
func isCodeField(k string) bool {
	n := norm(k)
	if codeFields[n] || strings.HasSuffix(n, "code") && n != "countrycode" && n != "zipcode" && n != "postcode" && n != "postalcode" && n != "currencycode" && n != "languagecode" {
		return true
	}
	for _, p := range []string{"totp", "otp", "mfa", "2fa", "tfa", "twofactor", "passcode"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func isCSRF(k string) bool {
	n := norm(k)
	return strings.Contains(n, "csrf") || strings.Contains(n, "xsrf") || n == "authenticitytoken" || n == "requestverificationtoken"
}

// classify names the page a recorded POST is, or "".
func classify(path, mime, body string) Page {
	ts := tokens(path)
	fields := fieldNames(mime, body)
	hasField := func(set map[string]bool) bool {
		for _, f := range fields {
			if set[norm(f)] {
				return true
			}
		}
		return false
	}
	hasCode := false
	for _, f := range fields {
		hasCode = hasCode || isCodeField(f)
	}
	switch {
	case (anyIn(ts, codeWords) || anyIn(ts, words("verify verification challenge")) && hasCode) && !anyIn(ts, notCodeWords):
		return Code
	case anyIn(ts, resetWords) || anyIn(ts, words("reset")) && anyIn(ts, passwordWords):
		return Reset
	case anyIn(ts, signUpWords) && !anyIn(ts, loginWords):
		return SignUp
	// A sign-up that its path does not name (Juice Shop's POST
	// /api/Users/): a password, the password again, and no current one.
	case hasField(passwordWords) && hasField(repeatFields) && !hasField(currentFields) &&
		!anyIn(ts, loginWords) && !anyIn(ts, passwordWords) && !anyIn(ts, words("change update reset")):
		return SignUp
	// A sign-up posted to a collection of users with no password repeat
	// (Mattermost's POST /api/v4/users): a password and a user name or
	// email address, and no current password.
	case userCollections[lastSegment(path)] && hasField(passwordWords) && hasField(idFields) && !hasField(currentFields):
		return SignUp
	}
	return ""
}

// fieldNames lists the top-level field names of a JSON object or form body.
func fieldNames(mime, body string) []string {
	var names []string
	if isJSONBody(mime, body) {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(body), &m) == nil {
			for k := range m {
				names = append(names, k)
			}
		}
		return names
	}
	for _, kv := range strings.Split(body, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k, err := url.QueryUnescape(k); err == nil {
			names = append(names, k)
		}
	}
	return names
}

func isJSONBody(mime, body string) bool {
	return strings.Contains(strings.ToLower(mime), "json") || startsJSON(body)
}

// template makes the body template of a recorded page, or says why it
// cannot.
func template(p Page, mime, body string) ([]byte, bool, string) {
	switch {
	case len(body) > maxBody:
		return nil, false, fmt.Sprintf("its body is longer than %d bytes", maxBody)
	case hasPH(body):
		return nil, false, holdsPH
	}
	changed := 0
	// value returns the template value of field k with string value v.
	value := func(k, v string) string {
		n := norm(k)
		switch p {
		case Reset:
			if isCSRF(k) || idFields[n] || isEmail(v) {
				return v
			}
		case Code:
			if !isCodeField(k) {
				return v
			}
		case SignUp:
			switch {
			case isEmail(v):
				changed++
				return newPH + "@" + newDomain
			case idFields[n] && !strings.Contains(n, "phone") && n != "mobile":
				changed++
				return newPH
			}
			return v
		}
		changed++
		return wrongPH
	}
	if isJSONBody(mime, body) {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(body))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			return nil, false, "its body is not a JSON object"
		}
		// A placeholder can hide behind an escape ("\u007bwrong}"): look
		// for one in the decoded body, which the encoder writes as is.
		if dec, err := encodeJSON(m); err != nil || hasPH(string(dec)) {
			return nil, false, holdsPH
		}
		for k, v := range m {
			m[k] = walk(k, v, value)
		}
		if changed == 0 && p != Reset {
			return nil, false, nothingToChange(p)
		}
		b, err := encodeJSON(m)
		if err != nil {
			return nil, false, err.Error()
		}
		return b, true, ""
	}
	if !strings.Contains(strings.ToLower(mime), "x-www-form-urlencoded") {
		return nil, false, fmt.Sprintf("its body is %q, not JSON or a form", mime)
	}
	if _, err := url.ParseQuery(body); err != nil {
		return nil, false, "its body is not a valid form"
	}
	var parts []string
	for _, kv := range strings.Split(body, "&") {
		rawK, rawV, _ := strings.Cut(kv, "=")
		k, _ := url.QueryUnescape(rawK)
		v, _ := url.QueryUnescape(rawV)
		if hasPH(k) || hasPH(v) { // escaped, as "%7Bwrong%7D"
			return nil, false, holdsPH
		}
		if nv := value(k, v); nv != v {
			// The placeholders are filled in escaped, so the rest of
			// the value is escaped now.
			rawV = strings.ReplaceAll(url.QueryEscape(strings.NewReplacer(wrongPH, "\x00w", newPH, "\x00n").Replace(nv)), "%00w", wrongPH)
			rawV = strings.ReplaceAll(rawV, "%00n", newPH)
		}
		parts = append(parts, rawK+"="+rawV)
	}
	if changed == 0 && p != Reset {
		return nil, false, nothingToChange(p)
	}
	return []byte(strings.Join(parts, "&")), false, ""
}

const holdsPH = "its body already holds {wrong} or {new}"

func hasPH(s string) bool { return strings.Contains(s, wrongPH) || strings.Contains(s, newPH) }

// encodeJSON writes v as compact JSON with "<", ">" and "&" kept as they
// are.
func encodeJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b.Bytes()), nil
}

// looseCodeLimit says why a code page's limit lets an attacker make more
// than NISTMaxFailures wrong guesses a day, or "". The wrong codes allowed
// per window are the limit header's number, or else the wrong codes
// answered before the limit; a day holds 86400 s / window windows. The
// odds are RFC 4226 section 6's sv/10^Digit with s = 1 and 6 digits, as
// 1-(1-10^-6)^v.
func looseCodeLimit(r Result) string {
	allowed, how := r.Limit, fmt.Sprintf("its rate-limit header allows %d requests", r.Limit)
	if allowed == 0 && !strings.HasSuffix(r.Signal, "first request") {
		allowed, how = r.Requests-1, fmt.Sprintf("it answered %d wrong codes before it %s", r.Requests-1, r.Signal)
	}
	if allowed <= 0 {
		return ""
	}
	const nist = "NIST SP 800-63B-4 section 3.2.2 allows no more than 100 failed attempts in a row before the factor is disabled"
	if r.Window <= 0 {
		if allowed <= NISTMaxFailures {
			return ""
		}
		return fmt.Sprintf("This verification-code page is limited, but %s per window, more than the 100 that %s; the headers do not say how long a window lasts, so SiegeKit cannot say how many guesses a day that gives. Allow a few wrong codes, then ask for a new code or lock the factor.", how, nist)
	}
	perDay := float64(allowed) * (24 * time.Hour).Seconds() / r.Window.Seconds()
	if perDay <= NISTMaxFailures {
		return ""
	}
	odds := func(v float64) float64 { return 100 * -math.Expm1(v*math.Log1p(-1e-6)) }
	return fmt.Sprintf("This verification-code page is limited, but %s per %s, so an attacker who has the password can make about %.0f wrong guesses a day, while %s. For a 6-digit code that is about a %.2g%% chance a day and %.2g%% in 30 days (RFC 4226 section 6: guesses / 10^digits). Allow a few wrong codes, then ask for a new code or lock the factor.", how, r.Window, perDay, nist, odds(perDay), odds(30*perDay))
}

func nothingToChange(p Page) string {
	switch p {
	case Code:
		return "no field of its body is named like a code (code, otp, totp, passcode, pin and similar), so SiegeKit cannot send a wrong one"
	case SignUp:
		return "no field of its body holds a user name or an email address, so each request would try the same account"
	}
	return "" // a reset may send only an address (Gitea's)
}

// walk replaces the string values of a JSON value: by its own key in an
// object, by the key that holds it in an array.
func walk(k string, v any, value func(k, v string) string) any {
	switch x := v.(type) {
	case string:
		return value(k, x)
	case json.Number:
		// A code sent as a number is still a code; other numbers (an
		// ID, a question number) are kept.
		if nv := value(k, x.String()); nv != x.String() {
			return nv
		}
	case map[string]any:
		for kk, vv := range x {
			x[kk] = walk(kk, vv, value)
		}
	case []any:
		for i, vv := range x {
			x[i] = walk(k, vv, value)
		}
	}
	return v
}

// isEmail reports whether v looks like an email address.
func isEmail(v string) bool {
	at := strings.IndexByte(v, '@')
	return at > 0 && at < len(v)-1 && !strings.ContainsAny(v, " \t\r\n<>") && strings.Contains(v[at:], ".")
}

// pageFindings are the findings of a reset, sign-up or code page.
func pageFindings(e *Endpoint, r Result, planned int) []findings.Finding {
	uri := strings.SplitN(e.URL, "?", 2)[0]
	mk := func(rule, title, msg string, sev findings.Severity, cwe string) []findings.Finding {
		f := findings.Finding{RuleID: rule, Title: title, Message: msg, Severity: sev, CWEs: []string{cwe}, Location: findings.Location{URI: uri}, Family: Family}
		f.Sources = []findings.Source{{Plugin: e.Page.ID(), RuleID: rule}}
		f.ComputeFingerprint()
		return []findings.Finding{f}
	}
	if r.Limited {
		if e.Page != Code {
			return nil
		}
		if msg := looseCodeLimit(r); msg != "" {
			return mk("code-limit-high", "Many wrong codes are allowed before a limit", msg, findings.Low, "CWE-307")
		}
		return nil
	}
	// Fewer requests than the default give no "not limited" finding (ADR
	// 0062 item 7); the pages always send the default.
	if r.Requests < planned || r.Changed > 0 || planned < DefaultRequests {
		return nil
	}
	switch e.Page {
	case Reset:
		if r.MailLimited() {
			return nil
		}
		head := fmt.Sprintf("%d password-reset requests to this page, one per second, with wrong answers where the page asks for one, all answered %d, with no 429 or 503 answer and no rate-limit header.", r.Requests, r.Baseline)
		title := fmt.Sprintf("No limit seen in %d password-reset requests", r.Requests)
		tail := fmt.Sprintf(" If there is no limit, limit reset requests per account and per client. SiegeKit does not see a limit set above %d requests or one per IP address.", planned)
		if m := r.Mail; m != nil && m.Settled && m.Emails > 0 {
			return mk("reset-not-limited", title,
				head+fmt.Sprintf(" The app sent an email for each: %s. So anyone can send an address at least %d reset emails (and texts, if the app sends them) and make at least %d guesses at reset answers.", m.said(r), r.Requests, r.Requests)+tail,
				findings.Low, "CWE-799")
		}
		why := " The answers do not show whether the app sent an email or a text each time: it may still limit those (Gitea answered 200 to 40 such requests and sent 1 email). Give " + mailcatcher.Flag + " with a local Mailpit the app sends its mail to, and SiegeKit counts them."
		if m := r.Mail; m != nil {
			why = " The answers do not show whether the app sent an email or a text each time, and the mail catcher did not settle it: " + m.said(r) + "."
		}
		return mk("reset-not-limited", title,
			head+why+fmt.Sprintf(" If it does not limit them, anyone can send an address at least %d reset messages, run up the cost of texts, and make at least %d guesses at reset answers.", r.Requests, r.Requests)+tail,
			findings.Low, "CWE-799")
	case SignUp:
		return mk("signup-not-limited", fmt.Sprintf("No limit seen in %d sign-ups", r.Requests),
			fmt.Sprintf("%d sign-ups to this page, one per second, each with a new user name, all answered %d, with no 429 or 503 answer and no rate-limit header: up to %d accounts were made, named siegekit-new-..., which you can delete. So anyone can make at least %d accounts in a row (spam, fake reviews, free-tier abuse) and, if the app confirms by email, send that many emails. If there is no limit, limit sign-ups per client, or add a CAPTCHA. SiegeKit does not see a limit set above %d requests or one per IP address.", r.Requests, r.Baseline, r.Accepted, r.Requests, planned),
			findings.Low, "CWE-799")
	}
	return mk("code-not-limited", fmt.Sprintf("No limit seen in %d wrong verification codes", r.Requests),
		fmt.Sprintf("%d wrong codes sent to this verification-code page, one per second, all answered %d, with no 429 or 503 answer, no rate-limit header and no change of answer, so an attacker who has the password can make at least %d guesses at the second factor. NIST SP 800-63B allows at most 100 failed attempts in a row; SiegeKit does not see a limit set above %d requests or one per IP address. If there is no limit, lock the login or ask for a new code after a few wrong codes.", r.Requests, r.Baseline, r.Requests, planned),
		findings.Medium, "CWE-307")
}
