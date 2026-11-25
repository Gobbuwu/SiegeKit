// MEASUREMENT PROTOTYPE, NOT FOR MERGE (#87): copied into internal/verify
// by the measuring workflow. The proof fetch behind a stand-in for Vercel
// Authentication, without and with the bypass header.
package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestZZProofBehindLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vercel-Protection-Bypass") != "s3cr3t-zz" {
			http.Redirect(w, r, "https://vercel.com/sso-api", http.StatusFound)
			return
		}
		fmt.Fprintln(w, "siegekit-verify=tok")
	}))
	defer srv.Close()
	su, _ := url.Parse(srv.URL)
	u, err := target.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr(su.Hostname())
	err = (&Checker{}).checkWellKnown(context.Background(), u, []netip.Addr{a}, "siegekit-verify=tok")
	t.Logf("ZZ proof fetch: H1=%v H2=%v err=%v", os.Getenv("SIEGEKIT_ZZ_HEADERS") != "", os.Getenv("SIEGEKIT_ZZ_VERCEL") != "", err)
}
