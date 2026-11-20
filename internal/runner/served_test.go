package runner

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// TestServedFindsPlantedIssues fetches the vulnerable app's start page and
// the files it links, then runs the pinned Gitleaks image over them as the
// served-secrets check does (ADR 0032): the key in the script and the one in
// its source map are reported at their URLs.
func TestServedFindsPlantedIssues(t *testing.T) {
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := sandbox.Detect()
	if err != nil {
		t.Fatal(err)
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(all, func(m *manifest.Manifest) bool { return m.ID == "gitleaks" })
	gl := all[i]
	if img, _ := ImageFor(gl); img != "" {
		if has, err := e.HasImage(context.Background(), img); err != nil {
			t.Fatal(err)
		} else if !has {
			if err := e.Pull(context.Background(), img); err != nil {
				t.Fatal(err)
			}
		}
	}
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	work := t.TempDir()
	dir := filepath.Join(work, "files")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := served.Collect(context.Background(), cfg, 100, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 || res.Requests != 3 {
		t.Fatalf("collected %+v", res)
	}
	run, err := Run(context.Background(), e, []*manifest.Manifest{gl}, Options{Version: "test", TargetDir: dir, WorkDir: work})
	if err != nil {
		t.Fatal(err)
	}
	if run.Plugins[0].Status != report.Ran {
		t.Fatalf("gitleaks: %+v", run.Plugins[0])
	}
	found := map[string]bool{}
	for _, f := range served.Findings(run.Findings, res) {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), servedToken) || strings.Contains(string(b), servedCloudKey) {
			t.Errorf("secret not masked: %s", b)
		}
	}
	for rule, issue := range vulnAppIssues[served.ID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s); found %v", issue, rule, found)
		}
	}
}
