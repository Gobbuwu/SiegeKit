package authz

import (
	"bufio"
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
)

func lines(t *testing.T, file string) [][]string {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, strings.Split(l, "\t"))
		}
	}
	return out
}

// The word list gives what the measurement gave on the two recordings, and
// skips every request that changed account data (ADR 0048).
func TestActionReasonMeasured(t *testing.T) {
	rows := lines(t, "testdata/measured-replays-2026-11-21.tsv")
	if len(rows) != 91 {
		t.Fatalf("%d rows", len(rows))
	}
	skipped := 0
	for _, r := range rows {
		got := ActionReason(r[1]) != ""
		if got != (r[2] == "true") {
			t.Errorf("%s %s: skipped %v, measured %s", r[0], r[1], got, r[2])
		}
		if got {
			skipped++
		}
	}
	if skipped != 3 {
		t.Errorf("skipped %d, measured 3", skipped)
	}
	for _, p := range []string{"/rest/user/change-password?current=a&new=b&repeat=b", "/rest/saveLoginIp"} {
		if ActionReason(p) == "" {
			t.Errorf("%s changed account B's data when replayed but is not skipped", p)
		}
	}
}

// No read of Gitea's API is skipped (held out: checked after the list was fixed).
func TestActionReasonHeldOut(t *testing.T) {
	rows := lines(t, "testdata/gitea-1.24.6-api-get-paths.txt")
	if len(rows) != 229 {
		t.Fatalf("%d paths", len(rows))
	}
	for _, r := range rows {
		if why := ActionReason("/api/v1" + r[0]); why != "" {
			t.Errorf("%s: %s", r[0], why)
		}
	}
}

func TestActionReason(t *testing.T) {
	for p, want := range map[string]string{
		"/rest/user/change-password?x=1":    `its path names the action "change"`,
		"/rest/saveLoginIp":                 `its path names the action "save"`,
		"/account/LOGOUT":                   `its path names the action "logout"`,
		"/items/5/delete":                   `its path names the action "delete"`,
		"/x/%64elete":                       `its path names the action "delete"`,
		"/api/item?action=deleteAll":        `its parameter action names the action "delete"`,
		"/api/item?Op=update":               `its parameter Op names the action "update"`,
		"/session?user=a&password=b":        `it sends the parameter "password"`,
		"/session?newPwd=b":                 `it sends the parameter "newPwd"`,
		"/rest/order-history":               "",
		"/alice/r/archive/main.zip":         "",
		"/user/login":                       "",
		"/notifications/subscriptions":      "",
		"/api/updates?since=1":              "",
		"/search?q=delete+account":          "",
		"/api/item?mode=delete":             "",
		"/user/settings/account":            "",
		"/r%C3%A9sum%C3%A9/remove%E2%80%8B": `its path names the action "remove"`,
	} {
		if got := ActionReason(p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestParseHARSkipsActions(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	var es []entry
	es = append(es, entry{"GET", "http://localhost:3000/rest/user/change-password?current=a&new=b&repeat=b"})
	for _, p := range []string{"/rest/saveLoginIp", "/a/delete", "/b/remove", "/c/reset", "/d/logout"} {
		es = append(es, entry{"GET", "http://localhost:3000" + p})
	}
	es = append(es, entry{"HEAD", "http://localhost:3000/e/update"}, entry{"GET", "http://localhost:3000/rest/basket/1"})
	h, err := ParseHAR(har(t, es, map[string]string{"Authorization": "Bearer A"}), tu)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Requests) != 1 || h.Requests[0].Path != "/rest/basket/1" || h.Action != 7 || len(h.ActionPaths) != 5 || h.ActionPaths[0] != "/rest/user/change-password" {
		t.Errorf("%+v", h)
	}
	// ZAP's attack scan (local only, ADR 0047) still gets them.
	if len(h.Recorded) != 8 {
		t.Errorf("recorded %d", len(h.Recorded))
	}
	s := Result{ATried: 1}.Summary(h, "", Counts{})
	if !strings.Contains(s, "7 naming an action that can change data, such as change, save or delete (ADR 0048) (/rest/user/change-password, /rest/saveLoginIp, /a/delete, /b/remove, /c/reset and 2 more) not replayed") || strings.Contains(s, "current=") {
		t.Error(s)
	}
	h.AddSpecRoutes([]string{"/users", "/users/remove", "/admin/install"}, "/api")
	if h.FromSpec != 1 || h.Action != 9 || len(h.Requests) != 2 {
		t.Errorf("spec: %+v", h)
	}
}

func TestCheckRefusesActions(t *testing.T) {
	tu := mustTarget(t, "http://127.0.0.1:1/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	_, err := Check(context.Background(), cfg, []Request{{Method: "GET", Path: "/ok"}, {Method: "GET", Path: "/rest/user/change-password?new=secret"}}, Accounts{B: http.Header{"Authorization": {"B"}}}, 1)
	if err == nil || !strings.Contains(err.Error(), "/rest/user/change-password is not replayed") || strings.Contains(err.Error(), "secret") {
		t.Errorf("%v", err)
	}
}
