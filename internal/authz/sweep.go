package authz

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// The route sweep (ADR 0052) sends every GET route in the app's API spec,
// not only the ones A's browser called, so it reaches a route no
// first-party client uses (Rocket.Chat's chat.getDeletedMessages, which
// leaks a private room's deleted-message IDs to any logged-in account).
// Each route's path and required parameters are filled from the IDs A's
// recording showed and the spec's own examples; the filled routes are
// replayed as A, C, B and no login by the existing check, and judged by
// the same read rule (ADR 0035, 0051). Writes are not swept here.

// MaxSweep is how many filled spec routes the sweep adds, on top of the
// HAR file's requests and the spec's parameterless routes (MaxRequests).
// Each is sent up to four times (A, C, B, no login). Set from the measured
// sizes of real specs (ADR 0052).
const MaxSweep = 300

// Sweep caps keep the sweep bounded.
const (
	maxIDsPerKey    = 8  // values kept under one harvested key
	maxIDsTotal     = 64 // values kept overall (the "all" bucket)
	maxFillPerRoute = 3  // ID candidates tried for one route
)

// reSweepID matches a token that looks like an object ID: a number, a
// UUID, 16 or more hex digits (Mongo ObjectId), or a 10-to-64 character
// word of letters and digits (Rocket.Chat's random IDs, e.g.
// "wKBW2YwrPahpag4zA"). The last shape needs at least one letter and one
// digit so plain words and slugs are left out.
var (
	reSweepStrict = regexp.MustCompile(`^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`)
	reSweepLoose  = regexp.MustCompile(`^[A-Za-z0-9_-]{10,64}$`)
	reHasLetter   = regexp.MustCompile(`[A-Za-z]`)
	reHasDigit    = regexp.MustCompile(`\d`)
)

// isID reports whether s looks like an object ID.
func isID(s string) bool {
	if reSweepStrict.MatchString(s) {
		return true
	}
	return reSweepLoose.MatchString(s) && reHasLetter.MatchString(s) && reHasDigit.MatchString(s)
}

// idSet holds the ID-shaped tokens A's recording showed, grouped by the
// normalized key they appeared under (a JSON field name or a query
// parameter), so a route's "roomId" parameter can be filled with values A
// used under roomId, rid and the like. "all" holds every value, for a
// path parameter no name matches.
type idSet struct {
	byKey map[string][]string
	all   []string
	seen  map[string]bool // value already in all
}

func newIDSet() *idSet {
	return &idSet{byKey: map[string][]string{}, seen: map[string]bool{}}
}

// normKey lowercases a key and drops everything but letters and digits, so
// "room_id", "roomId" and "Room-ID" all become "roomid".
func normKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// add records value v seen under key k.
func (s *idSet) add(k, v string) {
	if !isID(v) {
		return
	}
	nk := normKey(k)
	if nk != "" {
		vs := s.byKey[nk]
		if len(vs) < maxIDsPerKey && !containsStr(vs, v) {
			s.byKey[nk] = append(vs, v)
		}
	}
	if !s.seen[v] && len(s.all) < maxIDsTotal {
		s.seen[v] = true
		s.all = append(s.all, v)
	}
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// harvest collects IDs from one recorded request: its query string, its
// request body and its answer. JSON bodies are walked so a value is kept
// under its field name; a query keeps each value under its parameter name.
func (s *idSet) harvest(rawQuery string, body *harPostData, respText string) {
	if q, err := url.ParseQuery(rawQuery); err == nil {
		for k, vs := range q {
			for _, v := range vs {
				s.add(k, v)
			}
		}
	}
	if body != nil {
		s.harvestJSON(body.Text)
	}
	s.harvestJSON(respText)
}

// harvestJSON walks a JSON document and records string and number values
// that look like IDs under their field name. Non-JSON is ignored.
func (s *idSet) harvestJSON(text string) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > MaxAnswer {
		return
	}
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		return
	}
	s.walk("", v, 0)
}

func (s *idSet) walk(key string, v any, depth int) {
	if depth > 64 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			s.walk(k, e, depth+1)
		}
	case []any:
		for _, e := range x {
			s.walk(key, e, depth+1)
		}
	case string:
		s.add(key, x)
	case float64:
		if x == float64(int64(x)) {
			s.add(key, strconv.FormatInt(int64(x), 10))
		}
	}
}

// idAliases group the normalized parameter names that mean the same kind
// of object, so a "roomId" route parameter is filled from values A's
// recording showed under rid, channel and the like. A parameter whose
// normalized name is in a group is filled from every key in that group.
var idAliases = [][]string{
	{"roomid", "rid", "room", "channelid", "channel", "groupid", "group", "imid", "dmid", "tid"},
	{"userid", "uid", "user", "u"},
	{"messageid", "msgid", "mid", "message", "id"},
	{"fileid", "fid", "file", "uploadid"},
	{"teamid", "team"},
}

// idNameHint matches a parameter name that asks for an object ID, so the
// sweep fills it from harvested IDs rather than from a default.
var idNameHint = regexp.MustCompile(`(?i)(^|[^a-z])(id|rid|uid|mid|fid|tid|key|slug)([^a-z]|$)|id$`)

// candidates returns the harvested ID values that fit a parameter named
// name, best first: values seen under its own name, then under its
// aliases. It never returns more than maxFillPerRoute.
func (s *idSet) candidates(name string) []string {
	nk := normKey(name)
	var out []string
	add := func(k string) {
		for _, v := range s.byKey[k] {
			if !containsStr(out, v) {
				out = append(out, v)
			}
		}
	}
	add(nk)
	for _, g := range idAliases {
		if containsStr(g, nk) {
			for _, k := range g {
				add(k)
			}
		}
	}
	if len(out) > maxFillPerRoute {
		out = out[:maxFillPerRoute]
	}
	return out
}

// SpecParam is one parameter of a spec route: where it goes, whether it is
// required, and the spec's own hints for filling it.
type SpecParam struct {
	Name     string
	In       string // "path" or "query"
	Required bool
	Type     string // schema type, e.g. "string", "integer", "boolean"
	Format   string // schema format, e.g. "date-time"
	Example  string // the spec's example value, if any
}

// SpecRoute is one GET route of a spec with its path and query parameters.
type SpecRoute struct {
	Path   string
	Params []SpecParam
}

// reDateName matches a parameter name that asks for a date or time, so a
// required date parameter the spec typed only as a string (Rocket.Chat's
// "since") is filled with an early date, not the empty string.
var reDateName = regexp.MustCompile(`(?i)date|time|since|after|before|from$|until|^to$|updatedat|createdat`)

const epochDate = "1970-01-01T00:00:00.000Z"

// fillValue returns the value a non-ID required parameter is filled with:
// its spec example, else a default by type or name.
func (p SpecParam) fillValue() string {
	if p.Example != "" {
		return p.Example
	}
	switch strings.ToLower(p.Type) {
	case "integer", "number":
		return "0"
	case "boolean":
		return "false"
	}
	if strings.Contains(strings.ToLower(p.Format), "date") || reDateName.MatchString(p.Name) {
		return epochDate
	}
	return ""
}

// isIDParam reports whether a parameter asks for an object ID.
func (p SpecParam) isIDParam() bool {
	nk := normKey(p.Name)
	for _, g := range idAliases {
		if containsStr(g, nk) {
			return true
		}
	}
	return idNameHint.MatchString(p.Name)
}

// AddSweepRoutes adds the spec's GET routes, filled from A's harvested IDs
// and the spec's examples, after the HAR's own requests, at most MaxSweep
// (ADR 0052). base is the spec's base path ("" for the root).
// A route is dropped when a required path parameter, or a required
// ID-named query parameter, has no ID from A's recording to fill it: the
// sweep does not guess object IDs here (that is a separate item). Routes
// whose path names an action are left out (ADR 0048). The added routes
// carry every header of A's last session request (lastSession), like
// AddSpecRoutes.
func (h *HAR) AddSweepRoutes(routes []SpecRoute, base string) {
	session := h.lastSession()
	if session == nil {
		return
	}
	seen := map[string]bool{}
	for _, r := range h.Requests {
		seen[r.Method+" "+r.Path] = true
	}
	for _, rt := range routes {
		for _, full := range h.fillRoute(rt, base) {
			if seen["GET "+full] {
				continue
			}
			seen["GET "+full] = true
			if ActionReason(full) != "" {
				h.addAction(full)
				continue
			}
			if h.FromSweep >= MaxSweep {
				h.SweepOverLimit++
				continue
			}
			h.Requests = append(h.Requests, Request{Method: http.MethodGet, Path: full, Header: session.Clone()})
			h.FromSweep++
		}
	}
}

// lastSession returns the headers of A's last recorded request that has a
// session header, all of them, or nil. All of them, because an app may
// need a header beside the session one: Rocket.Chat refuses X-Auth-Token
// without X-User-Id (ADR 0052). Recorded headers are already limited to
// those a replay may send (replayHeaders). With none, nothing is added,
// because A's answer would be the same as no login (ADR 0035).
func (h *HAR) lastSession() http.Header {
	for i := len(h.Requests) - 1; i >= 0; i-- {
		hd := h.Requests[i].Header
		for _, k := range sessionHeaders {
			if len(hd.Values(k)) > 0 {
				return hd.Clone()
			}
		}
	}
	return nil
}

// fillRoute turns one spec route into the full paths to send: the path
// parameters replaced and a query string built. It returns an empty slice
// when a required path or ID-named query parameter cannot be filled.
func (h *HAR) fillRoute(rt SpecRoute, base string) []string {
	p := base + rt.Path
	// Path parameters: each needs an ID; the first few candidates are
	// tried. A required path parameter with no candidate drops the route.
	type seg struct {
		name   string
		values []string
	}
	var pathParams []seg
	for _, pm := range rt.Params {
		if pm.In != "path" {
			continue
		}
		vals := h.ids.candidates(pm.Name)
		if len(vals) == 0 {
			vals = h.ids.all
			if len(vals) > maxFillPerRoute {
				vals = vals[:maxFillPerRoute]
			}
		}
		if len(vals) == 0 {
			h.SweepNoID++
			return nil
		}
		pathParams = append(pathParams, seg{pm.Name, vals})
	}
	// Query parameters: required ones only. ID-named ones need a
	// candidate (else drop the route); others are filled from the spec.
	q := url.Values{}
	var idQuery []seg
	for _, pm := range rt.Params {
		if pm.In != "query" || !pm.Required {
			continue
		}
		if pm.isIDParam() {
			vals := h.ids.candidates(pm.Name)
			if len(vals) == 0 {
				h.SweepNoID++
				return nil
			}
			idQuery = append(idQuery, seg{pm.Name, vals})
			continue
		}
		q.Set(pm.Name, pm.fillValue())
	}
	// Expand the path and ID-query parameters over their candidates,
	// capped so one route cannot flood the sweep.
	combos := []map[string]string{{}}
	for _, sg := range append(pathParams, idQuery...) {
		var next []map[string]string
		for _, c := range combos {
			for _, v := range sg.values {
				m := map[string]string{}
				for k, x := range c {
					m[k] = x
				}
				m[sg.name] = v
				next = append(next, m)
				if len(next) >= maxFillPerRoute {
					break
				}
			}
		}
		combos = next
	}
	var out []string
	for _, c := range combos {
		path := p
		qv := cloneValues(q)
		for _, sg := range pathParams {
			path = replacePathParam(path, sg.name, c[sg.name])
		}
		for _, sg := range idQuery {
			qv.Set(sg.name, c[sg.name])
		}
		full := path
		if len(qv) > 0 {
			full += "?" + qv.Encode()
		}
		out = append(out, full)
	}
	return out
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// replacePathParam replaces {name} in a path with a URL-escaped value.
func replacePathParam(path, name, value string) string {
	return strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
}

// SweepRoutes returns the GET routes of an OpenAPI 3 or Swagger 2.0 spec,
// JSON or YAML, with their path and query parameters, resolving
// intra-document $ref parameters. YAML is read with go.yaml.in/yaml/v3,
// vendored (ADR 0052, owner's choice 2026-11-22).
func SweepRoutes(data []byte, format string) []SpecRoute {
	switch format {
	case "json":
	case "yaml":
		j, err := yamlToJSON(data)
		if err != nil {
			return nil
		}
		data = j
	default:
		return nil
	}
	var doc rawDoc
	if json.Unmarshal(trimBOM(data), &doc) != nil {
		return nil
	}
	var out []SpecRoute
	for p, item := range doc.Paths {
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#\\ \t\r\n\x00") {
			continue
		}
		get, ok := item["get"]
		if !ok {
			continue
		}
		var common []rawParam
		if raw, ok := item["parameters"]; ok {
			_ = json.Unmarshal(raw, &common)
		}
		var op rawOp
		if json.Unmarshal(get, &op) != nil {
			continue
		}
		params := doc.resolveParams(append(common, op.Parameters...))
		out = append(out, SpecRoute{Path: p, Params: params})
	}
	sortRoutes(out)
	return out
}

type rawDoc struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Parameters map[string]rawParam `json:"parameters"`
	} `json:"components"`
	Parameters map[string]rawParam `json:"parameters"` // Swagger 2.0
}

type rawOp struct {
	Parameters []rawParam `json:"parameters"`
}

type rawParam struct {
	Ref      string          `json:"$ref"`
	Name     string          `json:"name"`
	In       string          `json:"in"`
	Required bool            `json:"required"`
	Type     string          `json:"type"`
	Format   string          `json:"format"`
	Example  json.RawMessage `json:"example"`
	Schema   *struct {
		Type    string          `json:"type"`
		Format  string          `json:"format"`
		Example json.RawMessage `json:"example"`
	} `json:"schema"`
}

// resolveParams resolves $ref parameters and keeps the path and query
// ones, dropping duplicates by name and location.
func (d rawDoc) resolveParams(in []rawParam) []SpecParam {
	var out []SpecParam
	seen := map[string]bool{}
	for _, rp := range in {
		if rp.Ref != "" {
			rp = d.deref(rp.Ref)
		}
		if rp.Name == "" || (rp.In != "path" && rp.In != "query") {
			continue
		}
		key := rp.In + " " + rp.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		sp := SpecParam{Name: rp.Name, In: rp.In, Required: rp.Required || rp.In == "path", Type: rp.Type, Format: rp.Format, Example: scalarString(rp.Example)}
		if rp.Schema != nil {
			if sp.Type == "" {
				sp.Type = rp.Schema.Type
			}
			if sp.Format == "" {
				sp.Format = rp.Schema.Format
			}
			if sp.Example == "" {
				sp.Example = scalarString(rp.Schema.Example)
			}
		}
		out = append(out, sp)
	}
	return out
}

// deref resolves a local parameter $ref ("#/components/parameters/Name" or
// "#/parameters/Name"); anything else gives an empty parameter.
func (d rawDoc) deref(ref string) rawParam {
	name := ref[strings.LastIndex(ref, "/")+1:]
	if strings.HasPrefix(ref, "#/components/parameters/") {
		return d.Components.Parameters[name]
	}
	if strings.HasPrefix(ref, "#/parameters/") {
		return d.Parameters[name]
	}
	return rawParam{}
}

// scalarString renders a JSON scalar example as a string; a non-scalar
// (object or array) example is ignored.
func scalarString(raw json.RawMessage) string {
	raw = trimBOM(raw)
	if len(raw) == 0 || raw[0] == '{' || raw[0] == '[' || string(raw) == "null" {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		return b[3:]
	}
	return b
}

func sortRoutes(rs []SpecRoute) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Path < rs[j-1].Path; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

// maxYAMLNodes bounds the nodes visited while turning a YAML spec into
// JSON, aliases included, so a spec built to expand ("billion laughs")
// is refused instead of exhausting memory. The largest measured spec
// (Rocket.Chat's rooms.yaml, 694 KB) is far below it.
const maxYAMLNodes = 2_000_000

// yamlToJSON turns a YAML document into JSON. Scalars keep their text
// unless YAML tags them as a number, a boolean or null: a date such as
// Rocket.Chat's example "2018-12-12T00:11:22.345Z" stays a string, where
// decoding into Go values would make it a time.
func yamlToJSON(data []byte) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(trimBOM(data), &root); err != nil {
		return nil, err
	}
	budget := maxYAMLNodes
	v, err := yamlValue(&root, 0, &budget)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

var errYAMLTooBig = errors.New("the YAML spec is too deep or expands too far")

func yamlValue(n *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > 128 {
		return nil, errYAMLTooBig
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlValue(n.Content[0], depth+1, budget)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, nil
		}
		return yamlValue(n.Alias, depth+1, budget)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlValue(c, depth+1, budget)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			v, err := yamlValue(n.Content[i+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			var b bool
			if n.Decode(&b) == nil {
				return b, nil
			}
		case "!!int":
			var i int64
			if n.Decode(&i) == nil {
				return i, nil
			}
		case "!!float":
			var f float64
			if n.Decode(&f) == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
				return f, nil
			}
		}
		return n.Value, nil
	}
	return nil, nil
}
