package runner

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/publicmaps"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestPublicMapsFindsPlantedIssues runs the public-maps check against the
// vulnerable app with real requests (ADR 0046): both served specs and both
// source maps are reported, and nothing else.
func TestPublicMapsFindsPlantedIssues(t *testing.T) {
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	p, err := publicmaps.ProbeSpecs(context.Background(), egress.Get, cfg, 100)
	if err != nil || p.Tried != len(publicmaps.Paths()) || p.Requests != p.Tried {
		t.Fatalf("probe %+v %v", p, err)
	}
	dir := filepath.Join(t.TempDir(), "files")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := served.Collect(context.Background(), cfg, 100, dir)
	if err != nil {
		t.Fatal(err)
	}
	fs := publicmaps.Findings(p, res)
	found := map[string]bool{}
	for _, f := range fs {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
	}
	for rule, issue := range vulnAppIssues[publicmaps.ID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s); found %v", issue, rule, found)
		}
	}
	if len(fs) != len(vulnAppIssues[publicmaps.ID]) {
		t.Errorf("%d findings, want %d: %v", len(fs), len(vulnAppIssues[publicmaps.ID]), found)
	}
}
