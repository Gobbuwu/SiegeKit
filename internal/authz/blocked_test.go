package authz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// blockingApp answers the app for the first after requests of a check and
// then a 403 block page of about 25 KB to every request, the start-page
// fetches included (Vercel's checkpoint on Porchlet's R1p run, issue #86).
func blockingApp(t *testing.T, after int) (*httptest.Server, func() int) {
	t.Helper()
	page := "<html>" + strings.Repeat("checkpoint ", 2270) + "</html>"
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		check := !strings.HasSuffix(r.UserAgent(), "(start page check)")
		if check {
			n++
		}
		blocked := n > after
		mu.Unlock()
		if blocked {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, page)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q,"who":%q}`, r.URL.Path, r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// A block during the replay ends it at once (ADR 0071): the remaining
// requests are neither sent nor paced, and the replays read before the
// block are kept for F2. Before the fix the replay went on through every
// remaining request, each refused by the watch after a paced wait.
func TestCheckStopsWhenBlocked(t *testing.T) {
	srv, sent := blockingApp(t, 6)
	waits := noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	u := egress.NewWatch(cfg).Begin(context.Background())
	if u.Block() != nil {
		t.Fatal(u.Block().Reason)
	}
	cfg.Watch = u
	var es []entry
	for i := range 30 {
		es = append(es, entry{"GET", fmt.Sprintf("%s/api/items/%d", srv.URL, i)})
	}
	h, err := ParseHAR(har(t, es, map[string]string{"Authorization": "Bearer A"}), tu)
	if err != nil {
		t.Fatal(err)
	}
	// Requests 1 and 2 are sent as A, B and with no login. The block starts
	// at the 7th request: from then on A gets the block page, so each
	// recorded request is sent once, as A. The 10th block page in a row
	// (the 16th request, recorded request 12) stops the check; the other 18
	// are neither sent nor waited for.
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, 10)
	if !egress.IsBlocked(err) {
		t.Fatalf("err %v, want a BlockedError", err)
	}
	if sent() != 16 || res.Requests != 16 || len(*waits) != 15 {
		t.Errorf("sent %d, counted %d, %d waits; want 16, 16, 15", sent(), res.Requests, len(*waits))
	}
	// Requests 1 to 11 are kept (2 replayed in full, 9 refused to A by the
	// block page, which F2 then sees); request 12 was cut short.
	if len(res.Replays) != 11 || res.ATried != 12 || res.AFailed != 9 {
		t.Errorf("%d replays, %d tried", len(res.Replays), res.ATried)
	}
	if u.Block() == nil {
		t.Error("the watch saw no block")
	}
}

// The write replay stops on a refused request the same way.
func TestWriteCheckStopsWhenBlocked(t *testing.T) {
	srv, _ := writeApp(t)
	waits := noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	w := appWrites(t, srv)
	calls := 0
	old := send
	send = func(ctx context.Context, cfg egress.Config, method, path string, h http.Header, body []byte, max int64) (*egress.Answer, error) {
		calls++
		if calls > 3 {
			return nil, &egress.BlockedError{Block: &egress.Block{Reason: "test block"}}
		}
		return old(ctx, cfg, method, path, h, body, max)
	}
	t.Cleanup(func() { send = old })
	res, err := WriteCheck(context.Background(), cfg, w.Writes, Accounts{B: http.Header{"Authorization": {"Bearer B"}}}, "alice", 10, target.Local)
	if !egress.IsBlocked(err) {
		t.Fatalf("err %v, want a BlockedError", err)
	}
	if calls != 4 || res.Requests != 3 || len(*waits) != 3 {
		t.Errorf("%d calls, %d requests, %d waits; want 4, 3, 3", calls, res.Requests, len(*waits))
	}
}
