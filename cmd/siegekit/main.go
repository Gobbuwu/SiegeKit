// Command siegekit runs security tests against software you own.
//
// Milestone M1 in progress: passive scans of source directories are available.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const usage = `SiegeKit - local security testing for software you own.

Usage:
  siegekit scan [flags] DIR       scan a source directory (see: siegekit scan -h)
  siegekit plugins list           show the built-in checks and pinned tool versions
  siegekit plugins validate FILE...
  siegekit version

Only test systems you own or are authorized to test. See DISCLAIMER.md.
`

// Exit codes.
const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "siegekit %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "plugins":
		if len(args) >= 3 && args[1] == "validate" {
			return validate(args[2:], stdout, stderr)
		}
		if len(args) == 2 && args[1] == "list" {
			return list(stdout, stderr)
		}
	}
	fmt.Fprint(stderr, usage)
	return exitUsage
}

func validate(files []string, stdout, stderr io.Writer) int {
	code := exitOK
	for _, f := range files {
		m, err := manifest.Load(f)
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %s: %v\n", f, err)
			code = exitInvalid
			continue
		}
		fmt.Fprintf(stdout, "ok   %s (%s %s)\n", f, m.ID, m.Version)
	}
	return code
}

func list(stdout, stderr io.Writer) int {
	all, err := plugins.Builtin()
	if err != nil {
		fmt.Fprintf(stderr, "built-in plugins: %v\n", err)
		return exitInvalid
	}
	for _, m := range all {
		fmt.Fprintf(stdout, "%-10s %-8s %-8s %s %s (%s)\n", m.ID, m.Family, m.Mode, m.Tool.Name, m.Tool.Version, m.Tool.License)
	}
	return exitOK
}
