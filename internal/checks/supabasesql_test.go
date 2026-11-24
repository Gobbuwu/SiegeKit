package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The fixture's files mark each expected finding on its line with
// "FINDING rule-id severity"; everything else must stay quiet.
var reExpect = regexp.MustCompile(`FINDING ([a-z-]+) ([a-z]+)`)

func expected(t *testing.T, root string, ids ...string) []string {
	t.Helper()
	var want []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for i, l := range strings.Split(string(data), "\n") {
			if g := reExpect.FindStringSubmatch(l); g != nil && slices.Contains(ids, g[1]) {
				want = append(want, g[1]+"@"+filepath.ToSlash(rel)+":"+strconv.Itoa(i+1)+"/"+g[2])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(want)
	return want
}

func TestSupabaseRules(t *testing.T) {
	root := filepath.Join("testdata", "supabase-rules")
	o, err := backendRules.Run(context.Background(), root)
	fs := o.Findings
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, key(f))
		if f.Family != "iac" || f.Fingerprint == "" || len(f.CWEs) == 0 || f.Message == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	slices.Sort(got)
	want := expected(t, root, "supabase-table-without-rls", "supabase-rls-disabled", "supabase-policy-always-true",
		"supabase-view-bypasses-rls", "supabase-materialized-view-exposed", "supabase-storage-policy-open",
		"supabase-auth-short-passwords", "supabase-auth-email-unconfirmed", "supabase-auth-email-change-unconfirmed")
	if len(want) != 15 {
		t.Fatalf("fixture marks %d findings, want 15", len(want))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range fs {
		if f.RuleID == "supabase-table-without-rls" && f.Location.StartLine == 17 && !strings.Contains(f.Message, "renamed_to") {
			t.Errorf("renamed table reported under its old name: %s", f.Message)
		}
	}
}

func TestSupabaseSeedPassword(t *testing.T) {
	o, err := weakPasswords.Run(context.Background(), filepath.Join("testdata", "supabase-rules"))
	fs := o.Findings
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Location.URI != "supabase/seed.sql" || fs[0].Location.StartLine != 2 {
		t.Fatalf("want the crypt() seed password only, got %+v", fs)
	}
}

// The storage write test's gate fixtures (ADR 0059) are the known answers
// of the static rules too: the live test found s1, s2, s3, s5, s6, s7 and
// v1, v2, v3, v5, v6, v7 open to anyone, and s4 and v4 closed to anyone not
// signed in. s4 lets any signed-in user change everyone's files. s3 has two
// open policies (insert and delete), each its own finding.
func TestStorageGateSets(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "gate", "storage")
	want := map[string]string{
		"s1": "supabase-storage-policy-open/critical", "s2": "supabase-storage-policy-open/critical",
		"s3": "supabase-storage-policy-open/critical supabase-storage-policy-open/critical", "s4": "supabase-storage-policy-open/high",
		"s5": "supabase-storage-policy-open/critical", "s6": "supabase-storage-policy-open/critical",
		"s7": "supabase-storage-policy-open/critical",
		"v1": "firebase-public-access/critical", "v2": "firebase-public-access/critical",
		"v3": "firebase-public-access/high firebase-rule-without-auth/critical", "v4": "",
		"v5": "firebase-public-access/critical", "v6": "firebase-public-access/critical",
		"v7": "firebase-public-access/critical",
	}
	for set, w := range want {
		var files map[string]string
		if set[0] == 's' {
			data, err := os.ReadFile(filepath.Join(dir, "supabase", set+".sql.txt"))
			if err != nil {
				t.Fatal(err)
			}
			files = map[string]string{"supabase/migrations/1.sql": string(data)}
		} else {
			data, err := os.ReadFile(filepath.Join(dir, "firebase", set+".rules.txt"))
			if err != nil {
				t.Fatal(err)
			}
			files = map[string]string{"storage.rules": string(data)}
		}
		o, err := backendRules.Run(context.Background(), tree(t, files))
	fs := o.Findings
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			got = append(got, f.RuleID+"/"+f.Severity.String())
		}
		slices.Sort(got)
		if strings.Join(got, " ") != w {
			t.Errorf("%s: got %q, want %q", set, strings.Join(got, " "), w)
		}
	}
}

func TestOpenCommands(t *testing.T) {
	tr, f := "true", "x = 1"
	for _, tc := range []struct {
		cmd          string
		using, check *string
		want         string
	}{
		{"select", &tr, nil, "select"},
		{"insert", nil, &tr, "insert"},
		{"insert", nil, nil, ""}, // measured: refused
		{"update", nil, &tr, ""}, // measured: no row updated
		{"update", &tr, nil, "update"},
		{"update", &tr, &f, ""},
		{"delete", nil, nil, ""},    // measured: no row deleted
		{"all", nil, &tr, "insert"}, // measured: insert allowed, nothing visible
		{"all", &tr, nil, "select insert update delete"},
	} {
		p := &policy{cmd: tc.cmd, using: tc.using, check: tc.check}
		if got := strings.Join(openCommands(p, alwaysTrue), " "); got != tc.want {
			t.Errorf("%s using=%v check=%v: got %q, want %q", tc.cmd, tc.using != nil, tc.check != nil, got, tc.want)
		}
	}
}

func TestAlwaysTrue(t *testing.T) {
	for e, want := range map[string]bool{
		"true": true, " TRUE ": true, "(true)": true, "((true))": true, "1 = 1": true, "(1=1)": true,
		"(true) and (false)": false, "x": false, "true or x": false, "": false, "not true": false,
	} {
		if alwaysTrue(e) != want {
			t.Errorf("alwaysTrue(%q) = %v", e, !want)
		}
	}
}

func TestChecksCaller(t *testing.T) {
	for e, want := range map[string]bool{
		"bucket_id = '     '": false,
		"bucket_id = '     ' and (storage.foldername(name))[1] = '       '":       false,
		"bucket_id = '  ' and coalesce((metadata->>'    ')::bigint, 0) < 5242880": false,
		"bucket_id in (select id from storage.buckets where public)":              false,
		"owner = auth.uid()":                          true,
		"(select auth.uid()) = owner_id":              true,
		"auth . jwt() ->> 'role' = 'admin'":           true,
		"current_setting('request.jwt.claims') <> ''": true,
		"is_team_member(bucket_id)":                   true, // a function SiegeKit cannot read
		"true":                                        false,
	} {
		if checksCaller(e) != want {
			t.Errorf("checksCaller(%q) = %v", e, !want)
		}
	}
}

func TestInvokerOn(t *testing.T) {
	for o, want := range map[string]bool{
		"security_invoker": true, "security_invoker = true": true, "SECURITY_INVOKER=on": true,
		"security_invoker = '1'": true, "security_barrier, security_invoker = yes": true,
		"security_invoker = false": false, "security_barrier": false, "": false,
	} {
		if invokerOn(o) != want {
			t.Errorf("invokerOn(%q) = %v", o, !want)
		}
	}
}

func TestSupabaseGrants(t *testing.T) {
	run := func(sql string) []string {
		var out []string
		for _, f := range supabaseSQL(map[string][]byte{"supabase/migrations/1.sql": []byte(sql)}) {
			out = append(out, f.RuleID)
		}
		return out
	}
	for _, tc := range []struct{ name, sql, want string }{
		{"revoked by default privileges before create", "alter default privileges in schema public revoke all on tables from anon, authenticated;\ncreate table t (id int);", ""},
		{"default revoked then granted", "alter default privileges in schema public revoke all on tables from anon, authenticated;\ncreate table t (id int);\ngrant select on table t to anon;", "supabase-table-without-rls"},
		{"defaults for another role do not apply", "alter default privileges for role other in schema public revoke all on tables from anon, authenticated;\ncreate table t (id int);", "supabase-table-without-rls"},
		{"defaults for another schema do not apply", "alter default privileges in schema app revoke all on tables from anon, authenticated;\ncreate table t (id int);", "supabase-table-without-rls"},
		{"revoke all tables in schema", "create table t (id int);\nrevoke all on all tables in schema public from anon, authenticated;", ""},
		{"schema-wide revoke before create does not apply", "revoke all on all tables in schema public from anon, authenticated;\ncreate table t (id int);", "supabase-table-without-rls"},
		{"schema-wide revoke reaches views and materialized views", "create view v as select 1;\ncreate materialized view mv as select 1;\nrevoke select on all tables in schema public from anon, authenticated;", ""},
		{"own grant after schema-wide revoke", "create table t (id int);\nrevoke all on all tables in schema public from anon, authenticated;\ngrant select on t to anon;", "supabase-table-without-rls"},
		{"schema-wide revoke after own grant", "create table t (id int);\ngrant select on t to anon;\nrevoke all on all tables in schema public from anon, authenticated;", ""},
		{"replaced view keeps schema-wide revoke", "create view v as select 1;\nrevoke select on all tables in schema public from anon, authenticated;\ncreate or replace view v as select 2;", ""},
		{"revoke only from anon", "create table t (id int);\nrevoke all on t from anon;", "supabase-table-without-rls"},
		{"grant to public counts", "create table t (id int);\nrevoke all on t from anon, authenticated;\ngrant select on t to public;", "supabase-table-without-rls"},
		{"revoke grant option keeps the privilege", "create table t (id int);\nrevoke grant option for all on t from anon, authenticated;", "supabase-table-without-rls"},
		{"policy for a revoked role", "create table t (id int);\nalter table t enable row level security;\nrevoke insert on t from anon;\ncreate policy p on t for insert to anon with check (true);", ""},
		{"view revoked", "create view v as select 1;\nrevoke select on v from anon, authenticated;", ""},
		{"usage on schema is not a table grant", "create table t (id int);\nrevoke all on t from anon, authenticated;\ngrant usage on schema public to anon;\ngrant select on sequence s to anon;", ""},
		{"temporary table", "create temp table t (id int);", ""},
		{"table in another schema", "create table app.t (id int);", ""},
		{"policy renamed then dropped", "create table t (id int);\nalter table t enable row level security;\ncreate policy p on t for insert to anon with check (true);\nalter policy p on t rename to q;\ndrop policy q on t;", ""},
		{"policy altered to true", "create table t (id int);\nalter table t enable row level security;\ncreate policy p on t for delete to anon using (id = 1);\nalter policy p on t using (true);", "supabase-policy-always-true"},
		{"policies dropped with the table", "create table t (id int);\nalter table t enable row level security;\ncreate policy p on t for delete to anon using (true);\ndrop table t;\ncreate table t (id int);\nalter table t enable row level security;", ""},
		{"rls off with policies", "create table t (id int);\ncreate policy p on t for select using (owner = auth.uid());", "supabase-table-without-rls"},
		{"strings and comments are not SQL", "insert into x values ('create table t (id int)'); -- create table u (id int);\n/* alter table v disable row level security; */", ""},
	} {
		if got := strings.Join(run(tc.sql), " "); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFirebaseRuleWithoutAuth(t *testing.T) {
	for _, tc := range []struct{ name, rules, want string }{
		{"test mode", "allow read, write: if request.time < timestamp.date(2026, 12, 1);", "firebase-rule-without-auth/critical"},
		{"data-dependent read is not reported", "allow read: if resource.data.visibility == 'public';", ""},
		{"data-dependent write is", "allow read, update: if resource.data.visibility == 'public';", "firebase-rule-without-auth/critical"},
		{"shape-only create", "allow create: if request.resource.data.keys().hasOnly(['text']);", "firebase-rule-without-auth/critical"},
		{"auth check", "allow write: if request.auth != null && request.resource.size < 1000;", ""},
		{"auth through a function", "function signedIn() { return request.auth != null; }\nfunction owner(u) { return signedIn() && request.auth.uid == u; }\nallow write: if owner(uid);", ""},
		{"data through a function", "function isPublic() { return resource.data.public == true; }\nallow read: if isPublic();", ""},
		{"function without auth", "function small() { return request.resource.size < 1000; }\nallow write: if small();", "firebase-rule-without-auth/critical"},
		{"false", "allow write: if false;", ""},
		{"other document", "allow read: if get(/databases/$(database)/documents/config/site).data.open;", ""},
		{"multi-line condition", "allow write: if\n  request.resource.size < 1000\n  && request.resource.contentType.matches('image/.*');", "firebase-rule-without-auth/critical"},
	} {
		var got []string
		for _, f := range firebaseRules("firestore.rules", []byte("service cloud.firestore { match /d/{x} {\n"+tc.rules+"\n} }")) {
			got = append(got, f.RuleID+"/"+f.Severity.String())
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, strings.Join(got, " "), tc.want)
		}
	}
}

func TestSupabaseAuthConfig(t *testing.T) {
	cfg := "[auth]\nminimum_password_length = 8\n[auth.email]\nenable_confirmations = true\ndouble_confirm_changes = true\n[auth.sms]\nenable_confirmations = false\n[db]\nminimum_password_length = 1\n"
	if fs := supabaseAuthConfig("supabase/config.toml", []byte(cfg)); len(fs) != 0 {
		t.Fatalf("safe settings or other sections reported: %+v", fs)
	}
}

// A hostile repository must not make the replay quadratic: tables,
// policies, renames and schema-wide grants, at 256 KiB and at 1 MiB. Four
// times the input must take well under 16 times as long (quadratic); the
// best of three runs is compared so the bound holds under -race and on slow
// runners, where a fixed time limit failed before (M2 record, PR #42).
func TestSupabaseSQLLinear(t *testing.T) {
	gen := func(size int) []byte {
		var b strings.Builder
		for i := 0; b.Len() < size/4; i++ {
			fmt.Fprintf(&b, "create table t%d (i int);\ncreate policy p on t%d for select using (true);\n", i, i)
		}
		for i := 0; b.Len() < size/2; i++ {
			fmt.Fprintf(&b, "alter table t%d rename to r%d;\n", i, i)
		}
		for b.Len() < size {
			b.WriteString("grant select on all tables in schema public to anon;\n")
		}
		return []byte(b.String())
	}
	assertLinear(t, gen, func(data []byte) {
		supabaseSQL(map[string][]byte{"supabase/migrations/1.sql": data})
	})
}

// The same for Firebase rules: many allow statements and a long chain of
// functions.
func TestFirebaseRulesLinear(t *testing.T) {
	gen := func(size int) []byte {
		var b strings.Builder
		b.WriteString("service cloud.firestore {\nfunction f0() { return request.auth != null; }\n")
		for i := 0; b.Len() < size/2; i++ {
			fmt.Fprintf(&b, "function f%d() { return f%d(); }\n", i+1, i)
		}
		for b.Len() < size {
			b.WriteString("allow write: if f1() && request.resource.size < 1;\n")
		}
		return []byte(b.String())
	}
	assertLinear(t, gen, func(data []byte) { firebaseRules("firestore.rules", data) })
}

// assertLinear fails when run on a 1 MiB input from gen costs more than 8
// times run on a 256 KiB one (4x is linear). It counts this process's CPU
// time, best of 3 each, not the wall clock: other test packages run beside
// this one, and load that comes and goes between the two measurements made
// a linear run look 8x slower on CI (PR #74, reproduced with busy loops).
// No test in this package runs in parallel, so the CPU time is run's.
func assertLinear(t *testing.T, gen func(size int) []byte, run func([]byte)) {
	t.Helper()
	cpu := func() time.Duration {
		var r syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
			t.Fatal(err)
		}
		return time.Duration(r.Utime.Nano() + r.Stime.Nano())
	}
	best := func(data []byte) time.Duration {
		var d time.Duration
		for i := 0; i < 3; i++ {
			start := cpu()
			run(data)
			if e := cpu() - start; i == 0 || e < d {
				d = e
			}
		}
		return d
	}
	small, large := best(gen(MaxFileSize/4)), best(gen(MaxFileSize))
	t.Logf("CPU time: 256 KiB %v, 1 MiB %v", small, large)
	if large > 8*small+50*time.Millisecond {
		t.Fatalf("4x the input took %v vs %v of CPU time: not linear", large, small)
	}
}
