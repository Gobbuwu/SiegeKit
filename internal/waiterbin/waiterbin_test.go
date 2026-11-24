package waiterbin

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEmbeddedMatchesSource builds the waiter from source for every CPU type
// and requires the embedded programs to be the same bytes, so what SiegeKit
// runs in containers is the reviewed source. CI builds with GoVersion; any
// other Go release skips the test outside CI, and fails it in CI.
func TestEmbeddedMatchesSource(t *testing.T) {
	if runtime.Version() != GoVersion {
		if os.Getenv("CI") == "true" {
			t.Fatalf("CI runs %s, but the embedded waiters are built with %s: update GoVersion and run go generate ./internal/waiterbin", runtime.Version(), GoVersion)
		}
		t.Skipf("the embedded waiters are built with %s, this is %s", GoVersion, runtime.Version())
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range Arches {
		out := filepath.Join(t.TempDir(), "waiter")
		if err := Build(root, a, out); err != nil {
			t.Fatal(err)
		}
		built, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := Binary(a)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(built, embedded) {
			t.Errorf("embedded waiter for linux/%s differs from a build of the source (%d vs %d bytes): run GOTOOLCHAIN=%s go generate ./internal/waiterbin", a, len(embedded), len(built), GoVersion)
		}
	}
}

func TestBinaryUnknownArch(t *testing.T) {
	if _, err := Binary("riscv64"); err == nil {
		t.Fatal("want an error for an arch with no waiter")
	}
}
