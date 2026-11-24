// Package waiterbin holds the waiter (internal/waiter, ADR 0067) built as a
// static Linux program for each CPU type SiegeKit's containers run on. The
// files are built from source by "go generate ./internal/waiterbin" with the
// Go release named in GoVersion, and every CI job builds them again and
// fails if a byte differs (TestEmbeddedMatchesSource), so the embedded
// programs are the reviewed source. They are embedded rather than built
// with SiegeKit because SiegeKit itself may be a macOS or dynamically
// linked program, which cannot run inside a Linux container.
package waiterbin

//go:generate go run ./gen

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GoVersion is the Go release the embedded programs are built with: CI's
// (GO_VERSION in .github/workflows/ci.yml).
const GoVersion = "go1.27.4"

//go:embed bin/waiter-linux-amd64 bin/waiter-linux-arm64
var bins embed.FS

// Arches are the CPU types with an embedded waiter.
var Arches = []string{"amd64", "arm64"}

// Binary returns the waiter for linux/arch.
func Binary(arch string) ([]byte, error) {
	b, err := bins.ReadFile("bin/waiter-linux-" + arch)
	if err != nil {
		return nil, fmt.Errorf("no waiter for linux/%s", arch)
	}
	return b, nil
}

// Build builds the waiter for linux/arch from the module at root into out,
// reproducibly: static, no paths, no build ID, no version-control stamp.
// It runs the go command found on PATH, which must be GoVersion.
func Build(root, arch, out string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", out, "./cmd/siegekit-waiter") // #nosec G204 -- fixed arguments; out is the caller's path
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOFLAGS=-mod=vendor")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build waiter for %s: %v\n%s", arch, err, b)
	}
	return nil
}

// Path is where the embedded waiter for arch is kept in the repository.
func Path(root, arch string) string {
	return filepath.Join(root, "internal", "waiterbin", "bin", "waiter-linux-"+arch)
}
