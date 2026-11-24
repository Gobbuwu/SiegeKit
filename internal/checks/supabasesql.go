package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// Supabase SQL rules (ADR 0064 items 2 to 5). The migrations are replayed
// in name order, statement by statement, into a small model of the public
// schema and storage.objects: which tables and views exist, whether row-level
// security is on, which policies exist, and what anon and authenticated were
// granted or revoked. The rules then read the final state, the way Supabase's
// database linter (splinter) reads a live database.
//
// Statements are split at semicolons after comments and string contents are
// blanked (stripSQLComments). Dollar-quoted bodies are read like any other
// text, so a DO block that creates a policy counts, and so does DDL inside a
// function body, which only runs when the function is called (accepted, as
// before this ADR).

const (
	ident    = `(?:"[^"]+"|[a-z_][a-z0-9_$]*)`
	qualName = ident + `(?:\s*\.\s*` + ident + `)?`
	nameList = qualName + `(?:\s*,\s*` + qualName + `)*`
	privWord = `(?:all(?:\s+privileges)?|select|insert|update|delete|truncate|references|trigger|maintain)(?:\s*\([^)]*\))?`
	privList = privWord + `(?:\s*,\s*` + privWord + `)*`
	roleList = `(?:group\s+)?` + ident + `(?:\s*,\s*(?:group\s+)?` + ident + `)*`
)

var (
	reCmdStart = regexp.MustCompile(`(?i)\b(?:create|alter|drop|grant|revoke)\b`)

	reSQLCreateTable = regexp.MustCompile(`(?i)^create\s+(?:(?:global|local)\s+)?(?:(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(` + qualName + `)`)
	reSQLCreateView  = regexp.MustCompile(`(?i)^create\s+(?:or\s+replace\s+)?(?:(temp|temporary)\s+)?(?:recursive\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?(` + qualName + `)(?:\s*\([^)]*\))?(?:\s+with\s*\(([^)]*)\))?`)
	reSQLAlterTable  = regexp.MustCompile(`(?i)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(` + qualName + `)\s+(?:(enable|disable)\s+row\s+level\s+security|rename\s+to\s+(` + ident + `))`)
	reSQLAlterView   = regexp.MustCompile(`(?i)^alter\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?(` + qualName + `)\s+(?:(set|reset)\s*\(([^)]*)\)|rename\s+to\s+(` + ident + `))`)
	reSQLDrop        = regexp.MustCompile(`(?i)^drop\s+(?:table|(?:materialized\s+)?view)\s+(?:if\s+exists\s+)?(` + nameList + `)`)
	reSQLPolicy      = regexp.MustCompile(`(?i)^(create|alter|drop)\s+policy\s+(?:if\s+exists\s+)?(` + ident + `)\s+on\s+(` + qualName + `)`)
	reSQLGrant       = regexp.MustCompile(`(?i)^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(` + privList + `)\s+on\s+(?:(all\s+tables\s+in\s+schema\s+(` + ident + `(?:\s*,\s*` + ident + `)*))|(?:table\s+)?(` + nameList + `))\s+(?:to|from)\s+(` + roleList + `)`)
	reSQLDefault     = regexp.MustCompile(`(?i)^alter\s+default\s+privileges\s+(?:for\s+(?:role|user)\s+(` + roleList + `)\s+)?(?:in\s+schema\s+(` + ident + `(?:\s*,\s*` + ident + `)*)\s+)?(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(` + privList + `)\s+on\s+tables\s+(?:to|from)\s+(` + roleList + `)`)

	rePolicyAs    = regexp.MustCompile(`(?i)^\s*as\s+(permissive|restrictive)\b`)
	rePolicyFor   = regexp.MustCompile(`(?i)^\s*for\s+(all|select|insert|update|delete)\b`)
	rePolicyTo    = regexp.MustCompile(`(?i)^\s*to\s+(` + roleList + `)`)
	rePolicyUsing = regexp.MustCompile(`(?i)^\s*using\s*\(`)
	rePolicyCheck = regexp.MustCompile(`(?i)^\s*with\s+check\s*\(`)
	rePolicyRen   = regexp.MustCompile(`(?i)^\s*rename\s+to\s+(` + ident + `)`)
)

// Data API roles. "public" is every role, so it includes both.
const (
	roleAnon = "anon"
	roleAuth = "authenticated"
	rolePub  = "public"
)

var apiRoles = []string{roleAnon, roleAuth}

// Privileges the Data API uses, per command.
var commands = []string{"select", "insert", "update", "delete"}

// access is what one role may do on one relation.
type access int

const (
	accessPlatform access = iota // not granted or revoked by the migrations: the project's default
	accessGranted                // granted by the migrations
	accessRevoked                // revoked by the migrations
)

// stamp is a grant or revoke and the number of the statement that made it,
// so the latest one wins.
type stamp struct {
	access access
	seq    int
}

type relation struct {
	schema, name string
	kind         string // "table", "view", "materialized view"
	rel          string // file
	line         int
	rls          bool
	everRLS      bool // RLS was enabled at some point
	disableRel   string
	disableLine  int
	invoker      bool                        // views: security_invoker
	created      int                         // statement number of its creation
	acl          map[string]map[string]stamp // role -> privilege -> its own grant or revoke
}

type policy struct {
	name, table string // table is "schema.name"
	rel         string
	line        int
	restrictive bool
	cmd         string
	roles       []string
	using       *string
	check       *string
}

type sqlModel struct {
	rels     map[string]*relation          // "schema.name"
	schemas  map[string]map[string]bool    // schema -> keys of rels, for "all tables in schema"
	policies map[string]map[string]*policy // "schema.name" of the table -> policy name -> policy
	// Default privileges for new tables in public, per role and privilege.
	defaults map[string]map[string]stamp
	// The latest "grant/revoke ... on all tables in schema" per schema,
	// role and privilege. It applies to the relations that existed then;
	// keeping only the latest is enough, because a later one overrides an
	// earlier one for every relation both reach. This keeps a hostile file
	// of many such statements linear.
	bulk map[string]map[string]map[string]stamp
	seq  int // statements read so far
}

func newSQLModel() *sqlModel {
	return &sqlModel{rels: map[string]*relation{}, schemas: map[string]map[string]bool{}, policies: map[string]map[string]*policy{},
		defaults: map[string]map[string]stamp{}, bulk: map[string]map[string]map[string]stamp{}}
}

// relKey normalizes a possibly schema-qualified, possibly quoted name to
// "schema.name"; an unqualified name is in public (Supabase's search path).
func relKey(s string) string {
	parts := splitQualified(s)
	if len(parts) == 1 {
		return "public." + parts[0]
	}
	return parts[0] + "." + parts[1]
}

func splitQualified(s string) []string {
	var parts []string
	for _, p := range reDot.Split(strings.TrimSpace(s), -1) {
		parts = append(parts, identName(p))
	}
	return parts
}

func identName(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, `"`) {
		return strings.Trim(p, `"`)
	}
	return strings.ToLower(p)
}

var reDot = regexp.MustCompile(`\s*\.\s*`)

var reNameItem = regexp.MustCompile(`(?i)` + qualName)

func splitNames(list string) []string {
	return reNameItem.FindAllString(list, -1)
}

func splitRoles(list string) []string {
	var out []string
	for _, r := range strings.Split(list, ",") {
		r = strings.TrimSpace(r)
		r = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(r), "group "))
		out = append(out, identName(r))
	}
	return out
}

var reColumns = regexp.MustCompile(`\([^)]*\)`)

// splitPrivs lists privileges; "all" is the four the Data API uses, and a
// column list (select (a, b)) counts as the privilege.
func splitPrivs(list string) []string {
	var out []string
	for _, w := range strings.Split(reColumns.ReplaceAllString(list, ""), ",") {
		w = strings.ToLower(strings.TrimSpace(w))
		if strings.HasPrefix(w, "all") {
			out = append(out, commands...)
			continue
		}
		out = append(out, w)
	}
	return out
}

// statements splits cleaned SQL at semicolons and returns each statement's
// span, starting at its first command word (create, alter, drop, grant,
// revoke), so "do $$ begin create policy ..." starts at "create".
func statements(clean []byte) [][2]int {
	var out [][2]int
	start := 0
	for i := 0; i <= len(clean); i++ {
		if i < len(clean) && clean[i] != ';' {
			continue
		}
		if m := reCmdStart.FindIndex(clean[start:i]); m != nil {
			out = append(out, [2]int{start + m[0], i})
		}
		start = i + 1
	}
	return out
}

// apply replays one file.
func (m *sqlModel) apply(rel string, data []byte) {
	clean := stripSQLComments(data)
	ln := newLines(clean)
	for _, sp := range statements(clean) {
		m.seq++
		st := string(clean[sp[0]:sp[1]])
		line := ln.at(sp[0])
		switch {
		case m.createTable(rel, line, st):
		case m.createView(rel, line, st, string(data[sp[0]:sp[1]])):
		case m.alterTable(rel, line, st):
		case m.alterView(st, string(data[sp[0]:sp[1]])):
		case m.drop(st):
		case m.policy(rel, line, st):
		case m.grant(st):
		case m.defaultPrivs(st):
		}
	}
}

// put stores r under key, replacing any relation there.
func (m *sqlModel) put(key string, r *relation) {
	m.rels[key] = r
	if m.schemas[r.schema] == nil {
		m.schemas[r.schema] = map[string]bool{}
	}
	m.schemas[r.schema][key] = true
}

// remove forgets the relation at key and, with keepPolicies false, its
// policies (DROP TABLE drops them).
func (m *sqlModel) remove(key string, keepPolicies bool) {
	if r := m.rels[key]; r != nil {
		delete(m.schemas[r.schema], key)
	}
	delete(m.rels, key)
	if !keepPolicies {
		delete(m.policies, key)
	}
}

func (m *sqlModel) newRelation(key, kind, rel string, line int) *relation {
	r := &relation{kind: kind, rel: rel, line: line, created: m.seq, acl: map[string]map[string]stamp{}}
	r.schema, r.name, _ = strings.Cut(key, ".")
	// A new table or view takes the default privileges the migrations set
	// for public; the rest is the project's default.
	if r.schema == "public" {
		for role, privs := range m.defaults {
			r.acl[role] = map[string]stamp{}
			for p, a := range privs {
				r.acl[role][p] = stamp{a.access, m.seq}
			}
		}
	}
	return r
}

func (m *sqlModel) createTable(rel string, line int, st string) bool {
	g := reSQLCreateTable.FindStringSubmatch(st)
	if g == nil {
		return false
	}
	if g[1] != "" {
		return true // temporary tables are not reachable through the API
	}
	key := relKey(g[2])
	if _, seen := m.rels[key]; !seen {
		m.put(key, m.newRelation(key, "table", rel, line))
	}
	return true
}

func (m *sqlModel) createView(rel string, line int, st, orig string) bool {
	g := reSQLCreateViewIdx(st)
	if g == nil {
		return false
	}
	if g.temp {
		return true
	}
	key := relKey(g.name)
	kind := "view"
	if g.materialized {
		kind = "materialized view"
	}
	old := m.rels[key]
	r := m.newRelation(key, kind, rel, line)
	if old != nil && old.kind == kind {
		r.acl, r.created = old.acl, old.created // CREATE OR REPLACE keeps the grants
	}
	// CREATE OR REPLACE without WITH drops the options (measured on
	// PostgreSQL 16), so only this statement's options count. The option
	// values are read from the original text: the cleaned one blanks quotes.
	r.invoker = invokerOn(orig[g.optStart:g.optEnd])
	m.put(key, r)
	return true
}

type viewMatch struct {
	temp, materialized bool
	name               string
	optStart, optEnd   int
}

func reSQLCreateViewIdx(st string) *viewMatch {
	ix := reSQLCreateView.FindStringSubmatchIndex(st)
	if ix == nil {
		return nil
	}
	v := &viewMatch{temp: ix[2] >= 0, materialized: ix[4] >= 0, name: st[ix[6]:ix[7]]}
	if ix[8] >= 0 {
		v.optStart, v.optEnd = ix[8], ix[9]
	}
	return v
}

// invokerOn reports whether view options turn security_invoker on:
// "security_invoker", "security_invoker = true", "= on", "= 1", "= 'yes'".
func invokerOn(opts string) bool {
	for _, o := range strings.Split(opts, ",") {
		k, v, hasV := strings.Cut(o, "=")
		if strings.ToLower(strings.TrimSpace(k)) != "security_invoker" {
			continue
		}
		if !hasV {
			return true
		}
		switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `'"`)) {
		case "true", "on", "1", "yes", "t", "y":
			return true
		}
		return false
	}
	return false
}

func (m *sqlModel) alterTable(rel string, line int, st string) bool {
	g := reSQLAlterTable.FindStringSubmatch(st)
	if g == nil {
		return false
	}
	key := relKey(g[1])
	r := m.rels[key]
	switch {
	case r == nil:
	case strings.EqualFold(g[2], "enable"):
		r.rls, r.everRLS = true, true
	case strings.EqualFold(g[2], "disable"):
		r.rls, r.disableRel, r.disableLine = false, rel, line
	case g[3] != "":
		m.rename(key, r, g[3])
	}
	return true
}

func (m *sqlModel) alterView(st, orig string) bool {
	ix := reSQLAlterView.FindStringSubmatchIndex(st)
	if ix == nil {
		return false
	}
	key := relKey(st[ix[2]:ix[3]])
	r := m.rels[key]
	switch {
	case r == nil:
	case ix[4] >= 0 && strings.EqualFold(st[ix[4]:ix[5]], "set"):
		if strings.Contains(strings.ToLower(st[ix[6]:ix[7]]), "security_invoker") {
			r.invoker = invokerOn(orig[ix[6]:ix[7]])
		}
	case ix[4] >= 0: // reset
		if strings.Contains(strings.ToLower(st[ix[6]:ix[7]]), "security_invoker") {
			r.invoker = false
		}
	case ix[8] >= 0:
		m.rename(key, r, st[ix[8]:ix[9]])
	}
	return true
}

func (m *sqlModel) rename(key string, r *relation, to string) {
	m.remove(key, true)
	r.name = identName(to)
	nk := r.schema + "." + r.name
	m.put(nk, r)
	if ps := m.policies[key]; ps != nil {
		delete(m.policies, key)
		for _, p := range ps {
			p.table = nk
		}
		m.policies[nk] = ps
	}
}

func (m *sqlModel) drop(st string) bool {
	g := reSQLDrop.FindStringSubmatch(st)
	if g == nil {
		return false
	}
	for _, n := range splitNames(g[1]) {
		m.remove(relKey(n), false)
	}
	return true
}

func (m *sqlModel) policy(rel string, line int, st string) bool {
	ix := reSQLPolicy.FindStringSubmatchIndex(st)
	if ix == nil {
		return false
	}
	verb := strings.ToLower(st[ix[2]:ix[3]])
	name := identName(st[ix[4]:ix[5]])
	table := relKey(st[ix[6]:ix[7]])
	rest := st[ix[1]:]
	ps := m.policies[table]
	switch verb {
	case "drop":
		delete(ps, name)
		return true
	case "create":
		p := &policy{name: name, table: table, rel: rel, line: line, cmd: "all", roles: []string{rolePub}}
		parsePolicyClauses(p, rest)
		if ps == nil {
			ps = map[string]*policy{}
			m.policies[table] = ps
		}
		ps[name] = p
	case "alter":
		p := ps[name]
		if p == nil {
			return true
		}
		if g := rePolicyRen.FindStringSubmatch(rest); g != nil {
			delete(ps, name)
			p.name = identName(g[1])
			ps[p.name] = p
			return true
		}
		parsePolicyClauses(p, rest) // ALTER POLICY replaces only the clauses it names
	}
	return true
}

// parsePolicyClauses reads AS, FOR, TO, USING (...) and WITH CHECK (...) in
// order, as CREATE POLICY and ALTER POLICY write them.
func parsePolicyClauses(p *policy, s string) {
	for {
		if g := rePolicyAs.FindStringSubmatchIndex(s); g != nil {
			p.restrictive = strings.EqualFold(s[g[2]:g[3]], "restrictive")
			s = s[g[1]:]
			continue
		}
		if g := rePolicyFor.FindStringSubmatchIndex(s); g != nil {
			p.cmd = strings.ToLower(s[g[2]:g[3]])
			s = s[g[1]:]
			continue
		}
		if g := rePolicyTo.FindStringSubmatchIndex(s); g != nil {
			p.roles = splitRoles(s[g[2]:g[3]])
			s = s[g[1]:]
			continue
		}
		if g := rePolicyUsing.FindStringIndex(s); g != nil {
			e, n := balanced(s, g[1])
			p.using = &e
			s = s[n:]
			continue
		}
		if g := rePolicyCheck.FindStringIndex(s); g != nil {
			e, n := balanced(s, g[1])
			p.check = &e
			s = s[n:]
			continue
		}
		return
	}
}

// balanced returns the text up to the parenthesis that closes the one
// opened just before start, and the index after it.
func balanced(s string, start int) (string, int) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return s[start:i], i + 1
			}
		}
	}
	return s[start:], len(s)
}

func (m *sqlModel) grant(st string) bool {
	g := reSQLGrant.FindStringSubmatch(st)
	if g == nil {
		return false
	}
	a := accessGranted
	if strings.EqualFold(g[1], "revoke") {
		a = accessRevoked
	}
	if strings.Contains(strings.ToLower(st[:len(g[0])]), "grant option for") {
		return true // revoking only the grant option leaves the privilege
	}
	privs, roles := splitPrivs(g[2]), splitRoles(g[6])
	st2 := stamp{a, m.seq}
	if g[3] != "" {
		for _, s := range strings.Split(g[4], ",") {
			schema := identName(s)
			if m.bulk[schema] == nil {
				m.bulk[schema] = map[string]map[string]stamp{}
			}
			setACL(m.bulk[schema], roles, privs, st2)
		}
		return true
	}
	for _, n := range splitNames(g[5]) {
		if r := m.rels[relKey(n)]; r != nil {
			setACL(r.acl, roles, privs, st2)
		}
	}
	return true
}

func setACL(acl map[string]map[string]stamp, roles, privs []string, st stamp) {
	for _, role := range roles {
		if acl[role] == nil {
			acl[role] = map[string]stamp{}
		}
		for _, p := range privs {
			acl[role][p] = st
		}
	}
}

func (m *sqlModel) defaultPrivs(st string) bool {
	g := reSQLDefault.FindStringSubmatch(st)
	if g == nil {
		return false
	}
	// Migrations run as postgres; defaults for another role's objects do
	// not apply to theirs.
	if g[1] != "" && !containsStr(splitRoles(g[1]), "postgres") {
		return true
	}
	if g[2] != "" && !containsStr(splitRoles(g[2]), "public") {
		return true
	}
	a := accessGranted
	if strings.EqualFold(g[3], "revoke") {
		a = accessRevoked
	}
	if strings.Contains(strings.ToLower(st), "grant option for") {
		return true
	}
	setACL(m.defaults, splitRoles(g[5]), splitPrivs(g[4]), stamp{a, m.seq})
	return true
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// reach says whether role may use privilege priv on r: granted by the
// migrations (to the role or to public), revoked, or left to the project's
// default. Supabase granted anon and authenticated every table and view in
// public by default until its 2026 change (new projects from 2026-05-30,
// new objects in every project from 2026-10-30; self-hosted unchanged).
func (m *sqlModel) reach(r *relation, role, priv string) access {
	if m.own(r, rolePub, priv) == accessGranted {
		return accessGranted
	}
	return m.own(r, role, priv)
}

// own is the latest grant or revoke of priv to role on r: its own, or a
// schema-wide one made after r was created and after its own.
func (m *sqlModel) own(r *relation, role, priv string) access {
	o := r.acl[role][priv]
	if b := m.bulk[r.schema][role][priv]; b.seq > r.created && b.seq > o.seq {
		return b.access
	}
	return o.access
}

// reachable reports whether any API role may use any of privs on r, and
// whether that rests on an explicit grant.
func (m *sqlModel) reachable(r *relation, privs ...string) (bool, bool) {
	any, explicit := false, false
	for _, role := range apiRoles {
		for _, p := range privs {
			switch m.reach(r, role, p) {
			case accessGranted:
				any, explicit = true, true
			case accessPlatform:
				any = true
			}
		}
	}
	return any, explicit
}

const platformNote = "Supabase grants anon and authenticated access to every new table and view in public by default in self-hosted projects and in projects whose objects predate its 2026 change; newer ones need an explicit grant."

// findings turns the final model into findings.
func (m *sqlModel) findings() []findings.Finding {
	var out []findings.Finding
	keys := make([]string, 0, len(m.rels))
	for k := range m.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := m.rels[k]
		if r.schema != "public" {
			continue
		}
		switch r.kind {
		case "table":
			if f, ok := m.rlsFinding(k, r); ok {
				out = append(out, f)
			}
		case "view":
			if r.invoker {
				continue
			}
			if ok, explicit := m.reachable(r, "select"); ok {
				out = append(out, findings.Finding{
					RuleID:   "supabase-view-bypasses-rls",
					Title:    "Supabase view ignores row-level security",
					Message:  fmt.Sprintf("View %s is created without security_invoker = true, so it reads its tables with its owner's rights and row-level security does not apply: whoever can select from the view sees every row behind it. %s Use \"create view ... with (security_invoker = true)\" (PostgreSQL 15 and later) or move the view out of the public schema.", r.name, grantNote(explicit)),
					Severity: findings.High,
					CWEs:     []string{"CWE-284", "CWE-863"},
					Location: findings.Location{URI: r.rel, StartLine: r.line},
				})
			}
		case "materialized view":
			if ok, explicit := m.reachable(r, "select"); ok {
				out = append(out, findings.Finding{
					RuleID:   "supabase-materialized-view-exposed",
					Title:    "Supabase materialized view in the public schema",
					Message:  fmt.Sprintf("Materialized view %s is in the public schema. Materialized views cannot use row-level security, so whoever can select from it sees every row it holds. %s Move it to a schema the API does not expose, or revoke select from anon and authenticated.", r.name, grantNote(explicit)),
					Severity: findings.Medium,
					CWEs:     []string{"CWE-284"},
					Location: findings.Location{URI: r.rel, StartLine: r.line},
				})
			}
		}
	}
	var ps []*policy
	for _, byName := range m.policies {
		for _, p := range byName {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].table != ps[j].table {
			return ps[i].table < ps[j].table
		}
		return ps[i].name < ps[j].name
	})
	for _, p := range ps {
		if f, ok := m.policyFinding(p); ok {
			out = append(out, f)
		}
	}
	return out
}

func grantNote(explicit bool) string {
	if explicit {
		return "The migrations grant it to the API roles."
	}
	return platformNote
}

func (m *sqlModel) rlsFinding(key string, r *relation) (findings.Finding, bool) {
	if r.rls {
		return findings.Finding{}, false
	}
	ok, explicit := m.reachable(r, commands...)
	if !ok {
		return findings.Finding{}, false // revoked from anon and authenticated
	}
	n := len(m.policies[key])
	extra := grantNote(explicit)
	if n > 0 {
		extra = fmt.Sprintf("Its %d policies have no effect while RLS is off. %s", n, extra)
	}
	if !r.everRLS {
		return findings.Finding{
			RuleID:   "supabase-table-without-rls",
			Title:    "Supabase table without row-level security",
			Message:  fmt.Sprintf("Table %s is created without \"alter table %s enable row level security\". Tables in the public schema are reachable with the public anon key, so anyone could read or change every row. %s Enable RLS and add policies.", r.name, r.name, extra),
			Severity: findings.High,
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: r.rel, StartLine: r.line},
		}, true
	}
	return findings.Finding{
		RuleID:   "supabase-rls-disabled",
		Title:    "Supabase table has row-level security turned off again",
		Message:  fmt.Sprintf("Row-level security on table %s is enabled and later disabled here, so the table ends up without it: anyone with the public anon key could read or change every row. %s Remove the \"disable row level security\" or enable it again in a later migration.", r.name, extra),
		Severity: findings.High,
		CWEs:     []string{"CWE-284", "CWE-862"},
		Location: findings.Location{URI: r.disableRel, StartLine: r.disableLine},
	}, true
}

// What a policy lets through, per command, from the PostgreSQL rules
// (measured on 16.15): SELECT and DELETE use USING; INSERT uses WITH CHECK;
// UPDATE needs USING and checks the new row with WITH CHECK, or USING when
// there is none; FOR ALL uses USING for reads and WITH CHECK (or USING) for
// new rows. A missing clause lets nothing through.
func openCommands(p *policy, open func(string) bool) []string {
	is := func(e *string) bool { return e != nil && open(*e) }
	newRow := p.check
	if newRow == nil && (p.cmd == "all" || p.cmd == "update") {
		newRow = p.using
	}
	var out []string
	for _, c := range commands {
		if p.cmd != "all" && p.cmd != c {
			continue
		}
		var ok bool
		switch c {
		case "select", "delete":
			ok = is(p.using)
		case "insert":
			ok = is(newRow)
		case "update":
			ok = is(p.using) && is(newRow)
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

var reAlwaysTrue = regexp.MustCompile(`^(?:true|1=1)$`)

// alwaysTrue reports whether a policy expression is literally true, the
// patterns of splinter's rls_policy_always_true lint: true, (true), 1=1.
func alwaysTrue(e string) bool {
	s := strings.ToLower(strings.Join(strings.Fields(e), ""))
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		if _, n := balanced(s, 1); n != len(s) {
			break
		}
		s = s[1 : len(s)-1]
	}
	return reAlwaysTrue.MatchString(s)
}

var (
	reCallerRef = regexp.MustCompile(`(?i)\bauth\s*\.\s*[a-z_]+\s*\(|\b(?:current_user|session_user|current_role)\b|\bcurrent_setting\s*\(`)
	reCall      = regexp.MustCompile(`(?i)(` + qualName + `)\s*\(`)
	// Functions and keywords before "(" that say nothing about the caller.
	neutralCalls = map[string]bool{
		"storage.foldername": true, "storage.filename": true, "storage.extension": true,
		"foldername": true, "filename": true, "extension": true,
		"coalesce": true, "lower": true, "upper": true, "length": true, "char_length": true, "octet_length": true,
		"now": true, "array_length": true, "left": true, "right": true, "substring": true, "split_part": true,
		"nullif": true, "greatest": true, "least": true, "cardinality": true,
		"and": true, "or": true, "not": true, "in": true, "any": true, "all": true, "exists": true, "array": true,
		"select": true, "where": true, "when": true, "then": true, "else": true, "case": true, "values": true, "is": true,
	}
)

// checksCaller reports whether a storage policy expression depends on who
// is asking: it calls auth.uid(), auth.jwt() or auth.role(), reads the
// current user or request settings, or calls a function SiegeKit cannot read
// (which might). "bucket_id = 'avatars'" and size or name checks do not.
func checksCaller(e string) bool {
	if reCallerRef.MatchString(e) {
		return true
	}
	for _, g := range reCall.FindAllStringSubmatch(e, -1) {
		name := strings.ToLower(strings.Join(strings.Fields(g[1]), ""))
		if !neutralCalls[name] {
			return true
		}
	}
	return false
}

func (m *sqlModel) policyFinding(p *policy) (findings.Finding, bool) {
	if p.restrictive {
		return findings.Finding{}, false // AND-ed with the permissive ones: never widens access
	}
	storage := p.table == "storage.objects"
	var r *relation
	if !storage {
		r = m.rels[p.table]
		if r == nil || r.schema != "public" || r.kind != "table" || !r.rls {
			return findings.Finding{}, false // no table, not exposed, or the RLS rule reports it
		}
	}
	open := alwaysTrue
	if storage {
		open = func(e string) bool { return !checksCaller(e) }
	}
	cmds := openCommands(p, open)
	anon, auth := false, false
	for _, role := range p.roles {
		switch role {
		case roleAnon:
			anon = true
		case roleAuth:
			auth = true
		case rolePub:
			anon, auth = true, true
		}
	}
	// Who gets each open command, and how bad it is (ADR 0064 item 3).
	sev := findings.Severity(-1)
	var who []string
	raise := func(s findings.Severity, w string) {
		if s > sev {
			sev = s
		}
		who = append(who, w)
	}
	reaches := func(role, c string) bool {
		return storage || m.reach(r, role, c) != accessRevoked
	}
	for _, c := range cmds {
		switch {
		case anon && reaches(roleAnon, c) && c != "select":
			raise(findings.Critical, c+" by anyone")
		case anon && reaches(roleAnon, c) && !storage:
			// Often deliberate (a product list, public profiles); Supabase's
			// linter leaves SELECT out for that reason. Kept, low, because
			// a private table opened this way leaks every row.
			raise(findings.Low, c+" by anyone")
		case auth && reaches(roleAuth, c) && (c == "update" || c == "delete"):
			raise(findings.High, c+" by any signed-in user")
		case auth && reaches(roleAuth, c) && c == "insert":
			raise(findings.Medium, c+" by any signed-in user")
		}
	}
	if len(who) == 0 {
		return findings.Finding{}, false
	}
	if storage {
		return findings.Finding{
			RuleID:   "supabase-storage-policy-open",
			Title:    "Supabase storage policy lets anyone change files",
			Message:  fmt.Sprintf("Storage policy %q on storage.objects allows %s: its condition never checks who is asking (no auth.uid() or similar), only which bucket, folder or size. Supabase exposes storage to the public anon key, so this is open to whoever finds the bucket. Add a condition on the caller, such as (storage.foldername(name))[1] = auth.uid()::text, or limit the policy to authenticated users who own the file.", p.name, strings.Join(who, ", ")),
			Severity: sev,
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: p.rel, StartLine: p.line},
		}, true
	}
	_, table, _ := strings.Cut(p.table, ".")
	return findings.Finding{
		RuleID:   "supabase-policy-always-true",
		Title:    "Supabase policy allows every row",
		Message:  fmt.Sprintf("Policy %q on table %s is always true (using (true) or with check (true)), so row-level security lets through %s for every row. If the table really holds public data that anyone may read, a select policy like this is fine; for writes, add a condition such as auth.uid() = user_id.", p.name, table, strings.Join(who, ", ")),
		Severity: sev,
		CWEs:     []string{"CWE-284", "CWE-862"},
		Location: findings.Location{URI: p.rel, StartLine: p.line},
	}, true
}
