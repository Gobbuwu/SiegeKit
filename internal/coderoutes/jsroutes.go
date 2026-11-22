package coderoutes

import (
	"strings"
)

// The JavaScript and TypeScript extractor tokenizes each file (strings,
// template literals, comments and regular expression literals are told
// apart, so a route-shaped string in a comment or a regex is not read as
// code) and looks for two shapes:
//
//   - Rocket.Chat's REST API: API.v1.addRoute('name' or ['a', 'b'],
//     options, { get() {...}, post() {...} }) and the chained form
//     API.v1.get('name', options, handler).post(...), under /api/v1/
//     (API.default under /api/, API.experimental under /api/experimental/).
//   - Express: x.get('/path', handler), x.all('/path', ...),
//     x.route('/path').get(...), with a string path starting with "/".
//     A router mounted with app.use('/prefix', router) is not followed:
//     its routes are found without the prefix.
//
// The query parameters a handler reads are taken from this.queryParams
// (Rocket.Chat) and req.query (Express): member reads (.x, ['x']) and
// destructuring (const { a, b } = this.queryParams).

type jsTokKind int

const (
	tIdent jsTokKind = iota
	tString
	tTemplate // a template literal with ${...}: not a constant
	tNumber
	tPunct
	tRegex
)

type jsTok struct {
	kind jsTokKind
	text string // identifier, punctuation, or a string's value
}

type jsResult struct {
	routes     []found
	unresolved int
}

// jsScan adds the routes of one file to res.
func jsScan(src []byte, res *jsResult) {
	toks := tokenizeJS(src)
	scanRocketChat(toks, res)
	scanExpress(toks, res)
}

var jsRegexAfterWord = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "throw": true, "yield": true, "await": true, "instanceof": true,
}

// tokenizeJS splits source into tokens. It never fails: input it cannot
// read ends the token list early.
func tokenizeJS(src []byte) []jsTok {
	t := &jsTokenizer{src: src}
	t.run(false)
	return t.out
}

type jsTokenizer struct {
	src []byte
	i   int
	out []jsTok
}

func (t *jsTokenizer) regexAllowed() bool {
	if len(t.out) == 0 {
		return true
	}
	last := t.out[len(t.out)-1]
	switch last.kind {
	case tIdent:
		return jsRegexAfterWord[last.text]
	case tPunct:
		return last.text != ")" && last.text != "]" && last.text != "}"
	}
	return false
}

// run tokenizes until the end, or, with untilBrace, until the "}" that
// closes a template's ${.
func (t *jsTokenizer) run(untilBrace bool) {
	depth := 0
	src := t.src
	for t.i < len(src) {
		c := src[t.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			t.i++
		case c == '/' && t.i+1 < len(src) && src[t.i+1] == '/':
			for t.i < len(src) && src[t.i] != '\n' {
				t.i++
			}
		case c == '/' && t.i+1 < len(src) && src[t.i+1] == '*':
			end := strings.Index(string(src[t.i+2:]), "*/")
			if end < 0 {
				t.i = len(src)
			} else {
				t.i += end + 4
			}
		case c == '\'' || c == '"':
			s, ok := t.quoted(c)
			if !ok {
				return
			}
			t.out = append(t.out, jsTok{tString, s})
		case c == '`':
			s, dynamic := t.template()
			if dynamic {
				t.out = append(t.out, jsTok{tTemplate, ""})
			} else {
				t.out = append(t.out, jsTok{tString, s})
			}
		case c == '/' && t.regexAllowed():
			t.regex()
			t.out = append(t.out, jsTok{tRegex, ""})
		case isIdentStart(c):
			j := t.i
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			t.out = append(t.out, jsTok{tIdent, string(src[t.i:j])})
			t.i = j
		case c >= '0' && c <= '9':
			j := t.i
			for j < len(src) && (isIdentPart(src[j]) || src[j] == '.') {
				j++
			}
			t.out = append(t.out, jsTok{tNumber, string(src[t.i:j])})
			t.i = j
		default:
			if untilBrace {
				if c == '{' {
					depth++
				} else if c == '}' {
					if depth == 0 {
						t.i++
						return
					}
					depth--
				}
			}
			// Keep "?." and "..." as one token; others one byte.
			if c == '.' && t.i+2 < len(src) && src[t.i+1] == '.' && src[t.i+2] == '.' {
				t.out = append(t.out, jsTok{tPunct, "..."})
				t.i += 3
				continue
			}
			if c == '?' && t.i+1 < len(src) && src[t.i+1] == '.' && !(t.i+2 < len(src) && src[t.i+2] >= '0' && src[t.i+2] <= '9') {
				t.out = append(t.out, jsTok{tPunct, "."})
				t.i += 2
				continue
			}
			t.out = append(t.out, jsTok{tPunct, string(c)})
			t.i++
		}
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

// quoted reads a '...' or "..." string at t.i and returns its value with
// simple escapes undone.
func (t *jsTokenizer) quoted(q byte) (string, bool) {
	var b strings.Builder
	i := t.i + 1
	for i < len(t.src) {
		c := t.src[i]
		switch {
		case c == '\\' && i+1 < len(t.src):
			n := t.src[i+1]
			switch n {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '\n':
			default:
				b.WriteByte(n)
			}
			i += 2
		case c == q:
			t.i = i + 1
			return b.String(), true
		case c == '\n':
			t.i = i
			return b.String(), true // unterminated: stop the string here
		default:
			b.WriteByte(c)
			i++
		}
	}
	t.i = len(t.src)
	return b.String(), false
}

// template reads a template literal; dynamic when it holds ${...}, whose
// code is tokenized too.
func (t *jsTokenizer) template() (string, bool) {
	var b strings.Builder
	dynamic := false
	t.i++
	for t.i < len(t.src) {
		c := t.src[t.i]
		switch {
		case c == '\\' && t.i+1 < len(t.src):
			b.WriteByte(t.src[t.i+1])
			t.i += 2
		case c == '`':
			t.i++
			return b.String(), dynamic
		case c == '$' && t.i+1 < len(t.src) && t.src[t.i+1] == '{':
			dynamic = true
			t.i += 2
			inner := &jsTokenizer{src: t.src, i: t.i}
			inner.run(true)
			t.i = inner.i
		default:
			b.WriteByte(c)
			t.i++
		}
	}
	return b.String(), dynamic
}

// regex skips a regular expression literal at t.i.
func (t *jsTokenizer) regex() {
	i := t.i + 1
	class := false
	for i < len(t.src) {
		c := t.src[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\n':
			t.i = i
			return
		case c == '[':
			class = true
		case c == ']':
			class = false
		case c == '/' && !class:
			i++
			for i < len(t.src) && isIdentPart(t.src[i]) {
				i++
			}
			t.i = i
			return
		}
		i++
	}
	t.i = len(t.src)
}

// matchClose returns the index of the token closing the bracket at i, or
// -1.
func matchClose(toks []jsTok, i int) int {
	open := toks[i].text
	close := map[string]string{"(": ")", "[": "]", "{": "}"}[open]
	depth := 0
	for j := i; j < len(toks); j++ {
		if toks[j].kind != tPunct {
			continue
		}
		switch toks[j].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
			if depth == 0 {
				if toks[j].text != close {
					return -1
				}
				return j
			}
		}
	}
	return -1
}

// splitArgs returns the [start, end) token ranges of the arguments of the
// call whose "(" is at open and ")" at close.
func splitArgs(toks []jsTok, open, close int) [][2]int {
	var out [][2]int
	start, depth := open+1, 0
	for j := open + 1; j < close; j++ {
		if toks[j].kind != tPunct {
			continue
		}
		switch toks[j].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				out = append(out, [2]int{start, j})
				start = j + 1
			}
		}
	}
	if start < close {
		out = append(out, [2]int{start, close})
	}
	return out
}

// literalStrings returns the strings of an argument that is one string or
// an array of strings; ok is false for anything else.
func literalStrings(toks []jsTok, a [2]int) ([]string, bool) {
	n := a[1] - a[0]
	if n == 1 && toks[a[0]].kind == tString {
		return []string{toks[a[0]].text}, true
	}
	if n >= 2 && toks[a[0]].text == "[" && toks[a[1]-1].text == "]" {
		var out []string
		for j := a[0] + 1; j < a[1]-1; j++ {
			switch {
			case toks[j].kind == tString:
				out = append(out, toks[j].text)
			case toks[j].kind == tPunct && toks[j].text == ",":
			default:
				return nil, false
			}
		}
		return out, len(out) > 0
	}
	return nil, false
}

var rcBase = map[string]string{"v1": "/api/v1/", "default": "/api/", "experimental": "/api/experimental/"}

var jsHTTPMethods = map[string]string{"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH", "head": "HEAD", "options": "OPTIONS", "all": "*"}

// scanRocketChat finds API.<version> chains.
func scanRocketChat(toks []jsTok, res *jsResult) {
	for i := 0; i+3 < len(toks); i++ {
		if toks[i].kind != tIdent || toks[i].text != "API" || toks[i+1].text != "." || toks[i+2].kind != tIdent {
			continue
		}
		if i > 0 && toks[i-1].text == "." {
			continue // x.API.v1: not Rocket.Chat's
		}
		base, ok := rcBase[toks[i+2].text]
		if !ok {
			continue
		}
		j := i + 3
		for j+2 < len(toks) && toks[j].text == "." && toks[j+1].kind == tIdent {
			name := toks[j+1].text
			k := j + 2
			if toks[k].text == "<" { // TypeScript type arguments
				for k < len(toks) && toks[k].text != "(" {
					k++
				}
			}
			if k >= len(toks) || toks[k].text != "(" {
				break
			}
			end := matchClose(toks, k)
			if end < 0 {
				return
			}
			args := splitArgs(toks, k, end)
			switch {
			case name == "addRoute" && len(args) >= 2:
				rcAddRoute(toks, args, base, res)
			case jsHTTPMethods[name] == "GET" && len(args) >= 2:
				names, ok := literalStrings(toks, args[0])
				if !ok {
					res.unresolved++
					break
				}
				q := jsQueryParams(toks, args[len(args)-1])
				for _, n := range names {
					addJS(res, KindRocketChat, base+n, q)
				}
			}
			j = end + 1
		}
		i = j - 1
	}
}

// rcAddRoute reads addRoute(name(s), [options,] { get() {...}, ... }).
func rcAddRoute(toks []jsTok, args [][2]int, base string, res *jsResult) {
	last := args[len(args)-1]
	if toks[last[0]].text != "{" {
		return
	}
	// Keys of the methods object at its top level: get() / async get()
	// / get: function / get: { action() }.
	var getSpan *[2]int
	depth := 0
	for j := last[0]; j < last[1]; j++ {
		tk := toks[j]
		if tk.kind == tPunct {
			switch tk.text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			}
			continue
		}
		if depth != 1 || tk.kind != tIdent || tk.text != "get" || j+1 >= last[1] {
			continue
		}
		prev := toks[j-1]
		if !(prev.text == "{" || prev.text == "," || prev.text == "async") {
			continue
		}
		next := toks[j+1].text
		if next != "(" && next != ":" {
			continue
		}
		// The value runs to the next top-level comma of the object.
		end, d := j+1, 0
		for ; end < last[1]; end++ {
			if toks[end].kind == tPunct {
				switch toks[end].text {
				case "(", "[", "{":
					d++
				case ")", "]", "}":
					d--
				case ",":
					if d == 0 {
						goto done
					}
				}
				if d < 0 {
					break
				}
			}
		}
	done:
		getSpan = &[2]int{j, end}
		break
	}
	if getSpan == nil {
		return
	}
	names, ok := literalStrings(toks, args[0])
	if !ok {
		res.unresolved++
		return
	}
	q := jsQueryParams(toks, *getSpan)
	for _, n := range names {
		addJS(res, KindRocketChat, base+n, q)
	}
}

// scanExpress finds x.get('/path', ...), x.all('/path', ...) and
// x.route('/path').get(...).
func scanExpress(toks []jsTok, res *jsResult) {
	for i := 1; i+3 < len(toks); i++ {
		if toks[i].text != "." || toks[i+1].kind != tIdent || toks[i+2].text != "(" || toks[i-1].kind != tIdent && toks[i-1].text != ")" {
			continue
		}
		name := toks[i+1].text
		if isRCChain(toks, i) {
			continue
		}
		end := matchClose(toks, i+2)
		if end < 0 {
			return
		}
		args := splitArgs(toks, i+2, end)
		if len(args) == 0 {
			continue
		}
		paths, ok := literalStrings(toks, args[0])
		if ok {
			for _, p := range paths {
				if !strings.HasPrefix(p, "/") {
					ok = false
				}
			}
		}
		switch {
		case name == "route" && len(args) == 1 && ok:
			// x.route('/p').get(h).post(h)
			j := end + 1
			for j+2 < len(toks) && toks[j].text == "." && toks[j+1].kind == tIdent && toks[j+2].text == "(" {
				e := matchClose(toks, j+2)
				if e < 0 {
					return
				}
				if m := jsHTTPMethods[toks[j+1].text]; m == "GET" || m == "*" {
					q := jsQueryParams(toks, [2]int{j + 3, e})
					for _, p := range paths {
						addJS(res, KindExpress, p, q)
					}
				}
				j = e + 1
			}
		case (jsHTTPMethods[name] == "GET" || jsHTTPMethods[name] == "*") && len(args) >= 2:
			if !ok {
				// A path built at run time; count it only when it looks
				// like a route (a template or a "/" concatenation).
				if toks[args[0][0]].kind == tTemplate || toks[args[0][0]].kind == tString && strings.HasPrefix(toks[args[0][0]].text, "/") {
					res.unresolved++
				}
				continue
			}
			q := jsQueryParams(toks, [2]int{args[1][0], args[len(args)-1][1]})
			for _, p := range paths {
				addJS(res, KindExpress, p, q)
			}
		}
	}
}

// isRCChain reports whether the "." at i continues an API.<version>
// chain (handled by scanRocketChat).
func isRCChain(toks []jsTok, i int) bool {
	// Walk back over ").name(...)" links to the chain's start.
	j := i - 1
	for j >= 0 {
		if toks[j].text == ")" {
			depth := 0
			for ; j >= 0; j-- {
				if toks[j].text == ")" {
					depth++
				} else if toks[j].text == "(" {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			j-- // the method name
			if j < 1 || toks[j].kind != tIdent || toks[j-1].text != "." {
				return false
			}
			j -= 2
			continue
		}
		break
	}
	return j >= 2 && toks[j].kind == tIdent && rcBase[toks[j].text] != "" && toks[j-1].text == "." && toks[j-2].text == "API"
}

// jsQueryParams returns the query parameter names read in a handler's
// tokens: this.queryParams.x, req.query['x'], and
// { a, b: c, ...rest } = this.queryParams / req.query.
func jsQueryParams(toks []jsTok, span [2]int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for j := span[0]; j+1 < span[1]; j++ {
		if toks[j].text != "." || toks[j+1].kind != tIdent || (toks[j+1].text != "queryParams" && toks[j+1].text != "query") {
			continue
		}
		k := j + 2
		// Skip a TypeScript cast: ... as { roomId: string }.
		if k+1 < span[1] && toks[k].text == "." && toks[k+1].kind == tIdent {
			add(toks[k+1].text)
			continue
		}
		if k+2 < span[1] && toks[k].text == "[" && toks[k+1].kind == tString && toks[k+2].text == "]" {
			add(toks[k+1].text)
			continue
		}
		// Destructuring: walk back from "this"/"req" over "=" to "}".
		b := j - 1
		if b >= span[0] && toks[b].kind == tIdent {
			b--
		}
		if b >= span[0] && toks[b].text == "await" {
			b--
		}
		if b < span[0] || toks[b].text != "=" {
			continue
		}
		b--
		if b < span[0] || toks[b].text != "}" {
			continue
		}
		// Find the matching "{".
		depth := 0
		open := -1
		for x := b; x >= span[0]; x-- {
			if toks[x].text == "}" {
				depth++
			} else if toks[x].text == "{" {
				depth--
				if depth == 0 {
					open = x
					break
				}
			}
		}
		if open < 0 {
			continue
		}
		depth = 0
		for x := open + 1; x < b; x++ {
			tk := toks[x]
			if tk.kind == tPunct {
				switch tk.text {
				case "{", "[", "(":
					depth++
				case "}", "]", ")":
					depth--
				}
				continue
			}
			if depth != 0 || tk.kind != tIdent && tk.kind != tString {
				continue
			}
			prev := toks[x-1].text
			if prev != "{" && prev != "," {
				continue // a renamed target or a default value
			}
			add(tk.text)
		}
	}
	return out
}

func addJS(res *jsResult, kind, path string, q []string) {
	ps, ok := normalizePath(path)
	if !ok {
		res.unresolved++
		return
	}
	for _, p := range ps {
		res.routes = append(res.routes, found{kind: kind, path: p, query: q})
	}
}
