// Command gen rebuilds the embedded waiters (go generate ./internal/waiterbin).
// It must run with the Go release named in waiterbin.GoVersion.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Gobbuwu/SiegeKit/internal/waiterbin"
)

func main() {
	if runtime.Version() != waiterbin.GoVersion {
		fmt.Fprintf(os.Stderr, "gen: run with %s (GOTOOLCHAIN=%s go generate ./internal/waiterbin), not %s\n", waiterbin.GoVersion, waiterbin.GoVersion, runtime.Version())
		os.Exit(1)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, a := range waiterbin.Arches {
		if err := waiterbin.Build(root, a, waiterbin.Path(root, a)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
