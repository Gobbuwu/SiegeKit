package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

type writeCall struct {
	cfg       egress.Config
	ws        []authz.Write
	b         http.Header
	loginName string
	rate      float64
	mode      target.Mode
}

// useWriteCheck replaces the write replay and records its calls.
func useWriteCheck(t *testing.T, res authz.WriteResult) *[]writeCall {
	t.Helper()
	var calls []writeCall
	old := writeCheck
	writeCheck = func(_ context.Context, cfg egress.Config, ws []authz.Write, b http.Header, loginName string, rate float64, mode target.Mode) (authz.WriteResult, error) {
		calls = append(calls, writeCall{cfg, ws, b, loginName, rate, mode})
		return res, nil
	}
	t.Cleanup(func() { writeCheck = old })
	return &calls
}

// writesHAR is a recording with one read, A's create of item 7, its change,
// and a logout that is never replayed.
func writesHAR(t *testing.T) string {
	t.Helper()
	a := []map[string]string{{"name": "Authorization", "value": "Bearer A"}, {"name": "Content-Type", "value": "application/json"}}
	entries := []map[string]any{
		{"request": map[string]any{"method": "GET", "url": "http://localhost:3000/api/items", "headers": a}},
		{"request": map[string]any{"method": "POST", "url": "http://localhost:3000/api/items/", "headers": a, "postData": map[string]any{"mimeType": "application/json", "text": `{"product":1}`}},
			"response": map[string]any{"status": 201, "content": map[string]any{"text": `{"data":{"id":7}}`}}},
		{"request": map[string]any{"method": "PUT", "url": "http://localhost:3000/api/items/7", "headers": a, "postData": map[string]any{"mimeType": "application/json", "text": `{"qty":2}`}}},
		{"request": map[string]any{"method": "POST", "url": "http://localhost:3000/logout", "headers": a}},
	}
	b, err := json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "a.har")
	if err := os.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestScanURLWriteReplay(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	scanIn := func(tty bool, input string, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	plugin := func(id string) report.PluginResult {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatal(err)
		}
		for _, p := range r.Plugins {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("no %s in %+v", id, r.Plugins)
		return report.PluginResult{}
	}
	harFile := writesHAR(t)
	t.Setenv(authz.SessionEnv, "Authorization: Bearer B")
	changed := authz.WriteResult{Requests: 9, Recreated: 2, CleanedUp: 1, BTested: true, Replays: []authz.WriteReplay{{
		Write: authz.Write{Method: "PUT", Path: "/api/items/7"}, Who: authz.AsB, Sent: "/api/items/8", Recreated: true, Read: true,
		Before: authz.Answer{Status: 200, Body: []byte(`{"qty":1}`)}, Answer: authz.Answer{Status: 200}, After: authz.Answer{Status: 200, Body: []byte(`{"qty":2}`)},
	}}}

	// Write replay is local only and needs a recording.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--replay-writes", "http://localhost:3000/"}, "--replay-writes needs --har"},
		{[]string{"--replay-writes", "--har", harFile, "--deployed", "https://shop.example/"}, "runs only on local targets, not with --deployed"},
		{[]string{"--replay-writes", t.TempDir()}, "--replay-writes needs --har"},
	} {
		calls := useWriteCheck(t, changed)
		if code, out := scanIn(true, "", c.args...); code != exitUsage || !strings.Contains(out, c.want) || len(*calls) != 0 {
			t.Errorf("%v: exit %d\n%s", c.args, code, out)
		}
	}

	// Without --replay-writes the check is off, whatever the recording holds.
	useActive(t)
	useData(t)
	calls := useWriteCheck(t, changed)
	if code, out := scanIn(true, "test accounts\n", "--har", harFile, "--only", "access-control-write,zap", "http://localhost:3000/"); code != report.ExitClean || len(*calls) != 0 ||
		!strings.Contains(out, "access-control-write not run - off unless asked for") || strings.Contains(out, "test accounts") {
		t.Errorf("off: exit %d\n%s", code, out)
	}
	if p := plugin(authz.WriteID); p.Status != report.Skipped || p.Cause != report.CauseNoInput {
		t.Errorf("off: %+v", p)
	}

	// Each confirmation is needed: no terminal, "test accounts" not typed,
	// or "change test data" not typed. The read replay still runs after
	// "test accounts".
	for _, c := range []struct {
		tty         bool
		input, want string
		readRan     bool
	}{
		{false, "", "No flag skips this", false},
		{true, "no\n", `"test accounts" was not typed`, false},
		{true, "test accounts\nyes\n", `"change test data" was not typed`, true},
		{true, "test accounts\n", `"change test data" was not typed`, true},
	} {
		useActive(t)
		useData(t)
		calls := useWriteCheck(t, changed)
		reads := useAuthz(t, authz.Result{ATried: 1, Requests: 3, BTested: true}, nil)
		code, out := scanIn(c.tty, c.input, "--har", harFile, "--replay-writes", "--authorized-host", "localhost", "--only", "access-control,access-control-write,zap", "http://localhost:3000/")
		p := plugin(authz.WriteID)
		if len(*calls) != 0 || code != report.ExitClean || p.Status != report.Skipped || p.Cause != report.CauseNotConfirmed || !strings.Contains(p.Reason, c.want) || (len(*reads) == 1) != c.readRan {
			t.Errorf("%v %q: exit %d, %d writes, %d reads, %+v\n%s", c.tty, c.input, code, len(*calls), len(*reads), p, out)
		}
	}

	// Confirmed: the writes are listed, sent with a configuration that
	// allows them, in local mode, as B, and the change is a high finding.
	useActive(t)
	data := useData(t)
	calls = useWriteCheck(t, changed)
	useAuthz(t, authz.Result{ATried: 1, Requests: 3, BTested: true}, nil)
	code, out := scanIn(true, "test accounts\nchange test data\n", "--har", harFile, "--har-user", "alice", "--replay-writes", "--only", "access-control,access-control-write,zap", "http://localhost:3000/")
	if code != report.ExitFindings || len(*calls) != 1 ||
		!strings.Contains(out, "access-control replays requests, and access-control-write replays writes with the sessions of accounts A (the HAR file's session) and B (SIEGEKIT_SESSION_B)") ||
		!strings.Contains(out, "access-control-write siegekit 0.0.0-dev: replay 2 POST, PUT, PATCH and DELETE request(s) from a.har as account B and with no login") ||
		!strings.Contains(out, "access-control-write will send these 2 request(s) to http://localhost:3000/:\n  POST /api/items/\n  PUT /api/items/7\n") ||
		!strings.Contains(out, `Type "change test data" to run them: `) || strings.Contains(out, "  POST /logout\n") {
		t.Fatalf("exit %d, %d calls\n%s", code, len(*calls), out)
	}
	c := (*calls)[0]
	if c.cfg.ReadOnly || c.cfg.VerifyTLS || c.mode != target.Local || c.rate != 100 || c.loginName != "alice" || c.b.Get("Authorization") != "Bearer B" || len(c.ws) != 2 || c.ws[1].Create == nil || c.ws[1].Create.OldID != "7" {
		t.Errorf("call %+v", c)
	}
	p := plugin(authz.WriteID)
	if p.Status != report.Ran || p.Requests != 9 || p.Findings != 1 || p.Input != "a.har, 2 write(s) recorded as account A; account B from SIEGEKIT_SESSION_B" ||
		!strings.Contains(p.Result, "1 not replayed because they could log in, log out or lock an account out: POST /logout") || !strings.Contains(p.Result, "PUT /api/items/8 as account B") {
		t.Errorf("plugin %+v", p)
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	var e audit.Entry
	if err != nil || json.Unmarshal(b, &e) != nil || !slices.Contains(e.Plugins, authz.WriteID) {
		t.Errorf("audit entry %+v %v", e, err)
	}
	b, _ = os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	var r report.Run
	json.Unmarshal(b, &r)
	var found bool
	for _, f := range r.Findings {
		found = found || f.RuleID == "cross-account-write" && f.Severity == findings.High && f.Location.URI == "http://localhost:3000/api/items/7"
	}
	if !found {
		t.Errorf("findings %+v", r.Findings)
	}

	// --profile quick leaves it out.
	useActive(t)
	useData(t)
	calls = useWriteCheck(t, changed)
	if code, out := scanIn(true, "", "--profile", "quick", "--har", harFile, "--replay-writes", "--only", "access-control-write", "http://localhost:3000/"); code != exitInvalid || !strings.Contains(out, "--only names access-control-write, which --profile quick does not run") || len(*calls) != 0 {
		t.Errorf("quick: exit %d\n%s", code, out)
	}
}
