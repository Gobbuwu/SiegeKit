package authz

// Measurement only, not committed. Mirrors cmd/siegekit addSpecRequests
// (local target) followed by Check with B and C, as the CLI does.
import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestZZSweep(t *testing.T) {
	harPath := os.Getenv("ZZ_HAR")
	if harPath == "" {
		t.Skip()
	}
	data, _ := os.ReadFile(harPath)
	tu, _ := target.Parse(os.Getenv("ZZ_TARGET"))
	h, err := ParseHAR(data, tu)
	if err != nil {
		t.Fatal(err)
	}
	harN := len(h.Requests)
	if sp := os.Getenv("ZZ_SPEC"); sp != "" {
		b, _ := os.ReadFile(sp)
		format, err := openapi.Check(b)
		if err != nil {
			t.Fatal(err)
		}
		base, _ := openapi.BasePath(b, format)
		h.AddSpecRoutes(SpecRoutes(b, format), base)
		h.AddSweepRoutes(SweepRoutes(b, format), base)
	}
	fmt.Printf("PARSED har=%d spec=%d sweep=%d noid=%d action=%d over=%d sweepover=%d\n", harN, h.FromSpec, h.FromSweep, h.SweepNoID, h.Action, h.OverLimit, h.SweepOverLimit)
	var acc Accounts
	if s := os.Getenv("ZZ_B"); s != "" {
		acc.B, _ = ParseSession(s)
	}
	if s := os.Getenv("ZZ_C"); s != "" {
		acc.C, _ = ParseSessionFrom(SessionEnvC, s)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "measure", ReadOnly: true}
	res, err := Check(context.Background(), cfg, h.Requests, acc, 100)
	if err != nil {
		t.Fatal(err)
	}
	cw := res.CWorks()
	for i, r := range res.Replays {
		src := "har"
		if i >= harN {
			src = "spec"
		}
		short := func(a Answer) string {
			b := string(a.Body)
			if len(b) > 90 {
				b = b[:90]
			}
			return strings.ReplaceAll(b, "\n", " ")
		}
		fmt.Printf("RREPLAY %-4s %s %s A=%d/%d C=%d/%d B=%d/%d N=%d outsider=%v cross=%v bonly=%v Abody=%q Cbody=%q\n", src, r.Method, r.Path, r.A.Status, len(r.A.Body), r.C.Status, len(r.C.Body), r.B.Status, len(r.B.Body), r.None.Status, r.Outsider(), r.CrossAccount(), r.BOnly(cw), short(r.A), short(r.C))
	}
	fmt.Println("RSUMMARY requests", res.Requests, "rate429", res.Rate429, "cworks", cw)
	fmt.Println("RSUMMARYTEXT", res.Summary(h, os.Getenv("ZZ_USER"), Count(res, os.Getenv("ZZ_USER"))))
	for _, f := range Findings(tu.Origin(), res, os.Getenv("ZZ_USER")) {
		fmt.Println("RFINDING", f.RuleID, f.Severity, f.Location.URI)
	}
}
