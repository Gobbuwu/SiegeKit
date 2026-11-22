package login

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func mustTarget(t *testing.T, raw string) *target.URL {
	t.Helper()
	u, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParse(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/app/")
	l, err := Parse("http://localhost:3000/rest/user/login", `a"b\c`, `{"email":"{user}","password":"{password}"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(l.render(`p"w`), &v); err != nil || v["email"] != `a"b\c` || v["password"] != `p"w` {
		t.Errorf("JSON body %s: %v %v", l.render(`p"w`), v, err)
	}
	if l.ContentType() != "application/json" || l.Path != "/rest/user/login" || l.URL != "http://localhost:3000/rest/user/login" {
		t.Errorf("%+v", l)
	}
	f, err := Parse("http://localhost:3000/login", "a&b=c", "username={user}&password={password}", tu)
	if err != nil {
		t.Fatal(err)
	}
	q, err := url.ParseQuery(string(f.render("x&y")))
	if err != nil || q.Get("username") != "a&b=c" || q.Get("password") != "x&y" || f.ContentType() != "application/x-www-form-urlencoded" {
		t.Errorf("form body %s: %v %v", f.render("x&y"), q, err)
	}
	body := `{"u":"{user}","p":"{password}"}`
	for _, c := range []struct{ url, user, body, want string }{
		{"http://localhost:3001/login", "u", body, "not on the target's origin"},
		{"https://localhost:3000/login", "u", body, "not on the target's origin"},
		{"http://evil.test/login", "u", body, "not on the target's origin"},
		{"http://localhost:3000/login?next=/", "u", body, "must not have a query"},
		{"http://localhost:3000/login#x", "u", body, "must not have a fragment"},
		// Logged 2026-11-20, F6 of the full project check (ADR 0042).
		{"http://localhost:3000//x", "u", body, "single /"},
		{"http://localhost:3000//evil.test/login", "u", body, "single /"},
		{"ftp://localhost:3000/login", "u", body, "--login-url"},
		{"http://localhost:3000/login", "", body, "empty"},
		{"http://localhost:3000/login", "a\nb", body, "control characters"},
		{"http://localhost:3000/login", strings.Repeat("u", 257), body, "longer than"},
		{"http://localhost:3000/login", "u", `{"u":"{user}"}`, "must contain"},
		{"http://localhost:3000/login", "u", `password={password}`, "must contain"},
		{"http://localhost:3000/login", "u", `{"u":{user},"p":"{password}"}`, "not valid JSON"},
		{"http://localhost:3000/login", "u", "u={user}&p={password}&x=%zz", "not a valid form body"},
		{"http://localhost:3000/login", "u", "u={user}&p={password}" + strings.Repeat("x", 8<<10), "longer than"},
	} {
		if _, err := Parse(c.url, c.user, c.body, tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q, %q, %.40q): %v, want %q", c.url, c.user, c.body, err, c.want)
		}
	}
}

// fake replaces send and sleep: answer(i) answers the i-th login (from 0).
type fake struct {
	mu     sync.Mutex
	bodies []string
	waits  []time.Duration
}

func (f *fake) install(t *testing.T, answer func(i int) (*egress.Answer, error)) {
	oldSend, oldSleep, oldNow := send, sleep, now
	t.Cleanup(func() { send, sleep, now = oldSend, oldSleep, oldNow })
	start := time.Now()
	now = func() time.Time { return start }
	send = func(ctx context.Context, cfg egress.Config, method, path, ct string, body []byte, max int64) (*egress.Answer, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if method != http.MethodPost || path != "/login" || max != MaxAnswer {
			t.Errorf("sent %s %s max %d", method, path, max)
		}
		f.bodies = append(f.bodies, string(body))
		a, err := answer(len(f.bodies) - 1)
		if a != nil && a.Header == nil {
			a.Header = http.Header{}
		}
		return a, err
	}
	sleep = func(ctx context.Context, d time.Duration) error {
		f.waits = append(f.waits, d)
		return nil
	}
}

func testLogin(t *testing.T) (*Login, egress.Config) {
	tu := mustTarget(t, "http://localhost:3000/")
	l, err := Parse("http://localhost:3000/login", "tester", `{"user":"{user}","password":"{password}"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	return l, egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
}

func answer(status int, body string) *egress.Answer {
	return &egress.Answer{Status: status, Body: []byte(body), Took: 5 * time.Millisecond}
}

func TestCheckNoLimit(t *testing.T) {
	l, cfg := testLogin(t)
	var f fake
	f.install(t, func(int) (*egress.Answer, error) { return answer(401, `{"error":"Invalid email or password."}`), nil })
	r, err := Check(context.Background(), cfg, l, DefaultAttempts)
	if err != nil || r.Limited || r.Attempts != DefaultAttempts || r.Baseline != 401 {
		t.Fatalf("%+v %v", r, err)
	}
	// Exactly the planned number of logins, each with a new wrong password
	// for the test account, and a wait before each one after the first.
	if len(f.bodies) != DefaultAttempts || len(f.waits) != DefaultAttempts-1 {
		t.Fatalf("%d logins, %d waits", len(f.bodies), len(f.waits))
	}
	seen := map[string]bool{}
	for _, b := range f.bodies {
		var v map[string]string
		if err := json.Unmarshal([]byte(b), &v); err != nil || v["user"] != "tester" || !strings.HasPrefix(v["password"], "siegekit-wrong-") || len(v["password"]) != 35 || seen[v["password"]] {
			t.Errorf("login %s: %v", b, err)
		}
		seen[v["password"]] = true
	}
	for _, w := range f.waits {
		if w != Interval {
			t.Errorf("waited %s before a login, want %s", w, Interval)
		}
	}
	fs := Findings(l, r, DefaultAttempts)
	if len(fs) != 1 || fs[0].Severity != findings.Medium || fs[0].CWEs[0] != "CWE-307" || fs[0].Location.URI != "http://localhost:3000/login" ||
		fs[0].Sources[0].Plugin != ID || fs[0].Fingerprint == "" || !strings.Contains(fs[0].Message, "20 logins") || strings.Contains(fs[0].Message, "siegekit-wrong-") {
		t.Errorf("%+v", fs)
	}
	if !strings.Contains(r.Summary(DefaultAttempts), "no limit seen in 20 attempts, all answered 401") {
		t.Error(r.Summary(DefaultAttempts))
	}
}

func TestCheckLimited(t *testing.T) {
	retry := answer(401, "no")
	retry.Header = http.Header{"Retry-After": {"30"}}
	slow := answer(401, "no")
	slow.Took = 1500 * time.Millisecond
	for _, c := range []struct {
		name  string
		after *egress.Answer // the 4th answer
		want  string
	}{
		{"429", answer(429, ""), "answered 429"},
		{"423", answer(423, ""), "answered 423"},
		{"503", answer(503, ""), "answered 503"},
		{"retry-after", retry, "Retry-After"},
		{"status", answer(403, "no"), "answered 403 instead of 401"},
		{"captcha", answer(401, "Please solve the CAPTCHA"), `"captcha"`},
		{"too many", answer(401, "Too many failed attempts"), `"too many"`},
		{"slow", slow, "answered in 1.5s instead of 5ms"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, cfg := testLogin(t)
			var f fake
			f.install(t, func(i int) (*egress.Answer, error) {
				if i == 3 {
					return c.after, nil
				}
				return answer(401, "Invalid password"), nil
			})
			r, err := Check(context.Background(), cfg, l, DefaultAttempts)
			if err != nil || !r.Limited || r.Attempts != 4 || !strings.Contains(r.Signal, c.want) {
				t.Fatalf("%+v %v, want signal %q", r, err, c.want)
			}
			// The check stops at the first sign of a limit.
			if len(f.bodies) != 4 || Findings(l, r, DefaultAttempts) != nil {
				t.Errorf("%d logins sent", len(f.bodies))
			}
			if !strings.HasPrefix(r.Summary(DefaultAttempts), "limited after 4 of 20 attempts: ") {
				t.Error(r.Summary(DefaultAttempts))
			}
		})
	}
	// A word the first answer already had (a CAPTCHA widget on every page)
	// is not a limit; a slow answer under 1 second is not either.
	l, cfg := testLogin(t)
	var f fake
	f.install(t, func(i int) (*egress.Answer, error) {
		a := answer(401, "<div class=g-recaptcha></div> wrong password")
		if i > 0 {
			a.Took = 900 * time.Millisecond
		}
		return a, nil
	})
	if r, err := Check(context.Background(), cfg, l, 5); err != nil || r.Limited || r.Attempts != 5 {
		t.Errorf("%+v %v", r, err)
	}
}

func TestCheckFails(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(i int) (*egress.Answer, error)
		want   string
		sent   int
	}{
		{"404", func(int) (*egress.Answer, error) { return answer(404, ""), nil }, "answered 404 to a POST", 1},
		{"405", func(int) (*egress.Answer, error) { return answer(405, ""), nil }, "answered 405", 1},
		{"500 first", func(int) (*egress.Answer, error) { return answer(500, ""), nil }, "check --login-body", 1},
		{"no answer", func(int) (*egress.Answer, error) { return nil, io.EOF }, "did not answer", 1},
		{"500 later", func(i int) (*egress.Answer, error) {
			if i == 2 {
				return answer(500, ""), nil
			}
			return answer(401, ""), nil
		}, "answered 500 (a server error) after 2 login(s)", 3},
		{"stops answering", func(i int) (*egress.Answer, error) {
			if i == 2 {
				return nil, io.EOF
			}
			return answer(401, ""), nil
		}, "stopped answering after 2 login(s)", 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, cfg := testLogin(t)
			var f fake
			f.install(t, c.answer)
			if _, err := Check(context.Background(), cfg, l, DefaultAttempts); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v, want %q", err, c.want)
			}
			if len(f.bodies) != c.sent {
				t.Errorf("%d logins sent, want %d", len(f.bodies), c.sent)
			}
		})
	}
	// Limited at the very first login: said so, with no finding.
	l, cfg := testLogin(t)
	var f fake
	f.install(t, func(int) (*egress.Answer, error) { return answer(429, ""), nil })
	r, err := Check(context.Background(), cfg, l, DefaultAttempts)
	if err != nil || !r.Limited || r.Attempts != 1 || !strings.Contains(r.Signal, "already at the first attempt") {
		t.Errorf("%+v %v", r, err)
	}
}

// The attempt count and read-only (deployed) targets are checked before
// any login is sent.
func TestCheckLimits(t *testing.T) {
	l, cfg := testLogin(t)
	var f fake
	f.install(t, func(int) (*egress.Answer, error) { return answer(401, ""), nil })
	for _, n := range []int{-1, 0, 1, MaxAttempts + 1, 1000} {
		if _, err := Check(context.Background(), cfg, l, n); err == nil {
			t.Errorf("%d attempts accepted", n)
		}
	}
	cfg.ReadOnly = true
	if _, err := Check(context.Background(), cfg, l, DefaultAttempts); err == nil || !strings.Contains(err.Error(), "does not allow") {
		t.Errorf("read-only target: %v", err)
	}
	if len(f.bodies) != 0 {
		t.Errorf("%d logins sent", len(f.bodies))
	}
	cfg.ReadOnly = false
	if r, err := Check(context.Background(), cfg, l, MaxAttempts); err != nil || r.Attempts != MaxAttempts || len(f.bodies) != MaxAttempts {
		t.Errorf("%+v %v, %d sent", r, err, len(f.bodies))
	}
}

// A real server and the real clock: logins arrive at least a second apart.
func TestCheckRate(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/login" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s %s", r.Method, r.URL, r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	tu := mustTarget(t, srv.URL+"/")
	l, err := Parse(srv.URL+"/login", "tester", `{"user":"{user}","password":"{password}"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	r, err := Check(context.Background(), cfg, l, 3)
	if err != nil || r.Limited || r.Attempts != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	if len(times) != 3 {
		t.Fatalf("%d logins arrived", len(times))
	}
	for i := 1; i < len(times); i++ {
		if d := times[i].Sub(times[i-1]); d < 950*time.Millisecond {
			t.Errorf("logins %d and %d arrived %s apart", i, i+1, d)
		}
	}
	// Interrupting the run stops the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Check(ctx, cfg, l, 3); err == nil {
		t.Error("a cancelled run kept going")
	}
}

// FuzzLogin checks that any accepted user name is sent exactly as given,
// inside a valid JSON or form body.
func FuzzLogin(f *testing.F) {
	for _, s := range []string{"tester", `a"b\c`, "a&b=c%", "ü ", "{password}", "{user}"} {
		f.Add(s)
	}
	tu, _ := target.Parse("http://localhost:3000/")
	f.Fuzz(func(t *testing.T, user string) {
		j, err := Parse("http://localhost:3000/login", user, `{"u":"{user}","p":"{password}"}`, tu)
		if err != nil {
			return
		}
		var v map[string]string
		if err := json.Unmarshal(j.render("pw"), &v); err != nil || v["u"] != user || v["p"] != "pw" {
			t.Fatalf("JSON %s: %v %v", j.render("pw"), v, err)
		}
		fl, err := Parse("http://localhost:3000/login", user, "u={user}&p={password}", tu)
		if err != nil {
			t.Fatalf("form refused %q: %v", user, err)
		}
		q, err := url.ParseQuery(string(fl.render("pw")))
		if err != nil || q.Get("u") != user || q.Get("p") != "pw" {
			t.Fatalf("form %s: %v %v", fl.render("pw"), q, err)
		}
	})
}

func TestSpray(t *testing.T) {
	l, cfg := testLogin(t)
	var f fake
	f.install(t, func(int) (*egress.Answer, error) { return answer(401, `{"error":"Invalid user"}`), nil })
	r, err := Spray(context.Background(), cfg, l, 4)
	if err != nil || r.Limited || r.Attempts != 4 || r.Baseline != 401 || len(f.waits) != 3 {
		t.Fatalf("%+v %v waits %v", r, err, f.waits)
	}
	// Each login is for a new invented name, all with one wrong password,
	// never the test account.
	var password string
	for i, b := range f.bodies {
		var m map[string]string
		if err := json.Unmarshal([]byte(b), &m); err != nil {
			t.Fatal(err)
		}
		if m["user"] != fmt.Sprintf("siegekit-nobody-%d", i+1) || !strings.HasPrefix(m["password"], "siegekit-wrong-") || i > 0 && m["password"] != password {
			t.Errorf("login %d: %v", i, m)
		}
		password = m["password"]
	}
	fs := SprayFindings(l, r, 4)
	if len(fs) != 1 || fs[0].RuleID != "spray-not-limited" || fs[0].Severity != findings.Medium || fs[0].CWEs[0] != "CWE-307" || fs[0].Sources[0].Plugin != SprayID ||
		fs[0].Location.URI != "http://localhost:3000/login" || !strings.Contains(fs[0].Message, "4 logins for 4 different invented user names") {
		t.Errorf("%+v", fs)
	}
	// A limit, or fewer logins than planned, gives no finding.
	f = fake{}
	f.install(t, func(i int) (*egress.Answer, error) {
		if i == 2 {
			return answer(429, ""), nil
		}
		return answer(401, ""), nil
	})
	if r, err := Spray(context.Background(), cfg, l, 4); err != nil || !r.Limited || r.Attempts != 3 || len(SprayFindings(l, r, 4)) != 0 {
		t.Errorf("limited: %+v %v", r, err)
	}
	// An email login gets invented addresses at example.com.
	e := *l
	e.User = "tester@shop.test"
	if SprayUser(&e, 3) != "siegekit-nobody-3@example.com" || SprayUser(l, 3) != "siegekit-nobody-3" {
		t.Error(SprayUser(&e, 3), SprayUser(l, 3))
	}
}
