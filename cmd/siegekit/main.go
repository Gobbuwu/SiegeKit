// Command siegekit runs security tests against software you own.
//
// Milestone M1 (alpha) is complete: passive scans of source directories.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/docs"
	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/backend"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/publicmaps"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/relay"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const usage = `SiegeKit - local security testing for software you own.

Usage:
  siegekit scan [flags] DIR       scan a source directory (see: siegekit scan -h)
  siegekit scan [flags] URL       test a running web app you own (Linux; see: siegekit scan -h)
  siegekit update [--only a,b]    download vulnerability databases for offline scans
  siegekit plugins list           show the built-in checks and pinned tool versions
  siegekit plugins validate FILE...
  siegekit agents                 how AI coding assistants should use SiegeKit
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
	case "agents":
		fmt.Fprint(stdout, docs.Agents)
		return exitOK
	case relay.Command:
		// Runs inside the relay container of an active test (ADR 0021);
		// not listed in the help.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return relay.Main(ctx, args[1:], stdout, stderr)
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "update":
		return update(args[1:], stdout, stderr)
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
		fmt.Fprintf(stdout, "%-20s %-8s %-8s %s %s (%s)\n", m.ID, m.Family, m.Mode, m.Tool.Name, m.Tool.Version, m.Tool.License)
	}
	for _, c := range checks.Builtin() {
		fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", c.ID, c.Family, "passive", version)
	}
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", login.ID, login.Family, "active", version)
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", ratelimit.ID, ratelimit.Family, "active", version)
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", backend.ID, backend.Family, "active", version)
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", authz.ID, authz.Family, "active", version)
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s\n", publicmaps.ID, publicmaps.Family, "active", version)
	fmt.Fprintf(stdout, "%-20s %-8s %-8s built into SiegeKit %s, reads with gitleaks\n", served.ID, served.Family, "active", version)
	return exitOK
}
