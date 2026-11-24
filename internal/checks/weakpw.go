package checks

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/testpath"
)

// weakPasswords reports weak or factory-default passwords written into a
// project's own files (ADR 0034, owner answers 1b 2b 3a 4a 5a of
// 2026-11-20). It reads config files, credentials in URLs in any text file,
// and password-like assignments in source code in any language. It never
// tries a login.
const weakPasswordsID = "weak-passwords"

var weakPasswords = Check{
	ID:      weakPasswordsID,
	Name:    "Weak passwords in files",
	Family:  "secrets",
	Targets: []string{"repo"},
	Run:     runWeakPasswords,
}

// commonPasswords is SecLists Passwords/Common-Credentials/
// 10k-most-common.txt at commit 145f1f45ba7bc5fd6b3966d3a79bf95654deb20e
// (tag 2026.2), MIT; see THIRD_PARTY.md. A test checks its SHA-256.
//
//go:embed data/seclists-10k-most-common.txt
var commonPasswords []byte

// vendorDefaults are factory defaults and placeholders that the SecLists
// list does not all hold.
var vendorDefaults = []string{
	"admin", "root", "postgres", "changeme", "password", "secret", "toor", "guest", "test", "mysql",
	"sa", "oracle", "tomcat", "manager", "default", "letmein", "pass", "user", "demo", "example",
	"qwerty", "123456",
}

// minLength: a password shorter than this is reported as weak.
const minLength = 12

var weakList = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(string(commonPasswords), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m[strings.ToLower(l)] = true
		}
	}
	for _, v := range vendorDefaults {
		m[v] = true
	}
	return m
}()

// Why a file or a hit is skipped. Skipped hits are counted, not reported
// (answer 3a, extended after the 2026-11-20 measurement).
const (
	skipTemplate = "templates"
	skipTest     = "tests"
	skipI18n     = "translation files"
	skipDoc      = "documentation"
	skipComment  = "comments"
)

var skipOrder = []string{skipTest, skipI18n, skipDoc, skipComment, skipTemplate}

var (
	// generatedDirs hold build output; they are not read at all.
	generatedDirs = map[string]bool{"dist": true, "build": true, ".next": true}
	i18nDirs      = map[string]bool{"i18n": true, "locale": true, "locales": true, "lang": true, "translations": true, "l10n": true}
	docDirs       = map[string]bool{"doc": true, "docs": true, "guides": true}
	docExts       = map[string]bool{".md": true, ".rst": true, ".adoc": true, ".txt": true}
	confExts      = map[string]bool{".yml": true, ".yaml": true, ".json": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".properties": true, ".xml": true, ".sql": true, ".tf": true, ".tfvars": true}
	codeExts      = map[string]bool{".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".mjs": true, ".cjs": true, ".java": true, ".php": true, ".py": true, ".go": true, ".rb": true, ".cs": true, ".kt": true, ".rs": true, ".scala": true, ".swift": true}
	lockFiles     = map[string]bool{"package-lock.json": true, "yarn.lock": true, "composer.lock": true, "pnpm-lock.yaml": true}

	reTemplate = regexp.MustCompile(`(?i)\.(example|sample|template|dist)$`)
)

// A key that names a password: password, passwd, db_password, POSTGRES_PASSWORD,
// db.pass, admin-pwd; not bypass or passage.
const keyRE = `(?:[A-Za-z0-9_.\-]*(?:passw(?:or)?d|passwd)|(?:[A-Za-z0-9_.\-]*[_.\-])?(?:pass|pwd))`

var (
	reConfLine = regexp.MustCompile(`(?im)^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?(?:ENV[ \t]+|ARG[ \t]+)?(?P<k>` + keyRE + `):?[ \t]*[=:][ \t]*(?:"(?P<v>[^"\n]*)"|'(?P<v2>[^'\n]*)'|(?P<v3>[^\s#,"'][^#\n]*?))[ \t]*(?:#.*)?$`)
	reConfJSON = regexp.MustCompile(`(?i)"(?P<k>` + keyRE + `)"\s*:\s*"(?P<v>[^"]*)"`)
	reConfXML  = regexp.MustCompile(`(?i)<(?P<k>` + keyRE + `)>(?P<v>[^<]*)</`)
	reConfAttr = regexp.MustCompile(`(?i)\b(?P<k>` + keyRE + `)\s*=\s*"(?P<v>[^"]*)"`)
	reConfSQL  = regexp.MustCompile(`(?i)(?P<k>IDENTIFIED\s+BY|PASSWORD)\s+'(?P<v>[^']*)'`)
	// A password hashed in SQL, as Supabase seeds create users:
	// crypt('password123', gen_salt('bf')), also extensions.crypt(...)
	// (ADR 0064 item 6). Only a literal first argument counts.
	reSQLCrypt = regexp.MustCompile(`(?i)\b(?P<k>crypt)\s*\(\s*'(?P<v>[^']*)'\s*,`)
	reCode     = regexp.MustCompile(`(?i)\b(?P<k>` + keyRE + `)["']?\s*(?:=|:|=>|:=)\s*["'](?P<v>[^"'\n]*)["']`)
	reURL      = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://(?P<k>[^:/@\s"'<>]+):(?P<v>[^@/\s"'<>]+)@`)

	confPatterns = []*regexp.Regexp{reConfLine, reConfJSON, reConfXML, reConfAttr, reConfSQL}

	// A value that only points at a variable, or is a placeholder such as
	// {password} or <your-password>, is never reported.
	reVarRef = regexp.MustCompile(`(?i)#\{|\$\{|\$[A-Za-z_]|\{\{|%\(|<%|^\$|process\.env|os\.environ|getenv|^\{[A-Za-z_][A-Za-z0-9_.\-]*\}$|^<[^<>]+>$`)
	// Values that are not passwords: numbers and versions, YAML block markers.
	reNotPassword = regexp.MustCompile(`^(?:[\d.]+|[|>]-?)$`)
	reUser        = regexp.MustCompile(`(?i)(?:user(?:name)?|_user)\s*["']?\s*[=:]\s*["']?([^"'\s#,]+)`)
	rePassToken   = regexp.MustCompile(`(?i)[_.\-]?(passw(or)?d|passwd|pwd|pass)[_.\-]?`)
)

var notPasswords = map[string]bool{"true": true, "false": true, "null": true, "none": true, "nil": true, "yes": true, "no": true}

type weakHit struct {
	line   int
	key    string
	value  string
	reason string
	skip   string // non-empty: counted, not reported
}

func runWeakPasswords(ctx context.Context, root string) ([]findings.Finding, string, error) {
	var out []findings.Finding
	skipped := map[string]int{}
	err := walk(ctx, root, func(rel string) bool {
		for _, d := range strings.Split(path.Dir(rel), "/") {
			if generatedDirs[d] {
				return false
			}
		}
		base := path.Base(rel)
		return !lockFiles[base] && !strings.HasSuffix(base, ".min.js") && !strings.HasSuffix(base, ".map")
	}, func(rel string, data []byte) error {
		for _, h := range weakHits(rel, data) {
			if h.skip != "" {
				skipped[h.skip]++
				continue
			}
			out = append(out, weakFinding(rel, h))
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, weakSummary(len(out), skipped), nil
}

func weakSummary(reported int, skipped map[string]int) string {
	s := fmt.Sprintf("%d weak password(s) reported", reported)
	var parts []string
	total := 0
	for _, k := range skipOrder {
		if n := skipped[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d in %s", n, k))
			total += n
		}
	}
	if total > 0 {
		s += fmt.Sprintf("; %d not reported: %s", total, strings.Join(parts, ", "))
	}
	return s
}

// fileSkip says why every hit in the file at rel is skipped, if it is.
func fileSkip(rel string) string {
	base := path.Base(rel)
	ext := strings.ToLower(path.Ext(base))
	dirs := strings.Split(strings.ToLower(path.Dir(rel)), "/")
	switch {
	case testpath.IsTest(rel):
		return skipTest
	case anyDir(dirs, func(d string) bool { return i18nDirs[d] }):
		return skipI18n
	case docExts[ext] || anyDir(dirs, func(d string) bool { return docDirs[d] }):
		return skipDoc
	case reTemplate.MatchString(base):
		return skipTemplate
	}
	return ""
}

func anyDir(dirs []string, f func(string) bool) bool {
	for _, d := range dirs {
		if f(d) {
			return true
		}
	}
	return false
}

// weakHits finds the weak passwords in one file.
func weakHits(rel string, data []byte) []weakHit {
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil // binary
	}
	base := path.Base(rel)
	if m := reTemplate.FindStringIndex(base); m != nil && m[0] > 0 {
		base = base[:m[0]] // config.yml.example is read as config.yml
	}
	ext := strings.ToLower(path.Ext(base))
	isConf := confExts[ext] || strings.HasPrefix(base, ".env") || strings.HasPrefix(base, "Dockerfile")
	isCode := !isConf && codeExts[ext]
	txt := string(data)
	type cand struct {
		start, end    int // of the whole match
		keyAt, keyEnd int
		key, value    string
		conf          bool
	}
	var cands []cand
	add := func(re *regexp.Regexp, conf bool) {
		for _, m := range re.FindAllStringSubmatchIndex(txt, -1) {
			c := cand{start: m[0], end: m[1], conf: conf}
			for i, name := range re.SubexpNames() {
				if m[2*i] < 0 {
					continue
				}
				switch name {
				case "k":
					c.key, c.keyAt, c.keyEnd = txt[m[2*i]:m[2*i+1]], m[2*i], m[2*i+1]
				case "v", "v2", "v3":
					c.value = strings.TrimSpace(txt[m[2*i]:m[2*i+1]])
				}
			}
			cands = append(cands, c)
		}
	}
	if isConf {
		for _, re := range confPatterns {
			add(re, true)
		}
	}
	if ext == ".sql" {
		add(reSQLCrypt, true)
	}
	if isCode {
		add(reCode, false)
	}
	add(reURL, false)
	if len(cands) == 0 {
		return nil
	}
	users := map[string]bool{}
	for _, m := range reUser.FindAllStringSubmatch(txt, -1) {
		users[strings.ToLower(m[1])] = true
	}
	fskip := fileSkip(rel)
	ix := newTextIndex(txt)
	type seenKey struct {
		line  int
		value string
	}
	seen := map[seenKey]bool{}
	var hits []weakHit
	for _, c := range cands {
		v := c.value
		if v == "" || reVarRef.MatchString(v) || strings.HasSuffix(v, ":") || notPasswords[strings.ToLower(v)] || reNotPassword.MatchString(v) || strings.Contains(v, "%s") {
			continue
		}
		if !c.conf && quotedAlone(txt, c.keyAt, c.keyEnd) {
			continue
		}
		line := ix.count(ix.newlines, 1, c.start) + 1
		if seen[seenKey{line, v}] {
			continue
		}
		seen[seenKey{line, v}] = true
		reason := weakReason(v, c.key, users)
		if reason == "" {
			continue
		}
		h := weakHit{line: line, key: c.key, value: v, reason: reason, skip: fskip}
		if h.skip == "" && ix.inComment(c.start, !c.conf) {
			h.skip = skipComment
		}
		hits = append(hits, h)
	}
	return hits
}

// quotedAlone reports whether the key at [at:end] opens with a quote that
// does not close right after it, as in addCriterion("password =", value):
// the key is then part of a longer string, not a name being set.
func quotedAlone(txt string, at, end int) bool {
	if at == 0 || (txt[at-1] != '"' && txt[at-1] != '\'') {
		return false
	}
	return end >= len(txt) || txt[end] != txt[at-1]
}

// weakReason says why v is weak, or "" if it is not (answer 2b).
func weakReason(v, key string, users map[string]bool) string {
	lv := strings.ToLower(v)
	switch {
	case weakList[lv]:
		return "it is one of the 10,000 most common passwords or a vendor default"
	case users[lv]:
		return "it is the same as the user name"
	}
	if k := strings.ToLower(rePassToken.ReplaceAllString(key, "")); k != "" && lv == k {
		return "it is the same as the name it is set for"
	}
	if utf8.RuneCountInString(v) < minLength {
		return fmt.Sprintf("it is shorter than %d characters", minLength)
	}
	return ""
}

var commentPrefixes = []string{"#", "//", "/*", "*", "--", ";", "<!--"}

// textIndex holds where line breaks and block-comment markers are in a
// file, so each hit is placed in logarithmic time: a hostile file with many
// hits must not take quadratic time.
type textIndex struct {
	txt                                  string
	newlines, triple2, triple1, beg, end []int
}

func newTextIndex(txt string) *textIndex {
	return &textIndex{txt: txt, newlines: positions(txt, "\n"), triple2: positions(txt, `"""`), triple1: positions(txt, "'''"), beg: positions(txt, "=begin"), end: positions(txt, "=end")}
}

// positions lists where sub starts in txt, non-overlapping, left to right,
// as strings.Count counts them.
func positions(txt, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(txt[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(sub)
	}
}

// count is the number of occurrences, of length n, that end at or before pos.
func (x *textIndex) count(ps []int, n, pos int) int {
	return sort.SearchInts(ps, pos-n+1)
}

// last is the start of the last occurrence, of length n, that ends at or
// before pos, or -1.
func (x *textIndex) last(ps []int, n, pos int) int {
	if i := x.count(ps, n, pos); i > 0 {
		return ps[i-1]
	}
	return -1
}

// inComment reports whether the match at pos sits in a comment: its line
// starts with a comment marker, or, in code, it is inside a Python
// triple-quoted string or a Ruby =begin block.
func (x *textIndex) inComment(pos int, code bool) bool {
	ls := x.last(x.newlines, 1, pos) + 1
	prefix := strings.TrimLeft(x.txt[ls:pos], " \t")
	for _, p := range commentPrefixes {
		if strings.HasPrefix(prefix, p) {
			return true
		}
	}
	if !code {
		return false
	}
	return x.count(x.triple2, 3, pos)%2 == 1 || x.count(x.triple1, 3, pos)%2 == 1 ||
		x.last(x.beg, 6, pos) > x.last(x.end, 4, pos)
}

func weakFinding(rel string, h weakHit) findings.Finding {
	f := findings.Finding{
		RuleID:   "weak-password",
		Title:    "Weak password written in a file",
		Message:  fmt.Sprintf("%s sets %s to a weak password (%s): %s. Anyone who guesses it gets in. A setting for local development only is fine only if it never reaches a deployed system; otherwise use a long random password and read it from the environment or a secrets manager.", rel, h.key, h.reason, findings.MaskSecret(h.value)),
		Severity: findings.Medium,
		CWEs:     []string{"CWE-521", "CWE-798"},
		Location: findings.Location{URI: rel, StartLine: h.line},
		Family:   "secrets",
		Sources:  []findings.Source{{Plugin: weakPasswordsID, RuleID: "weak-password"}},
	}
	f.ComputeFingerprint()
	return f
}
