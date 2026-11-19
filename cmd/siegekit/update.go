package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

const updateUsage = `Usage: siegekit update [--only a,b] [--yes | --no-install]

Downloads the data some checks need, such as vulnerability databases, into
~/.local/share/siegekit/data. Each download runs in a container that has
network access but none of your files. Scans then use the data offline.
If a tool's container image is missing, SiegeKit asks before downloading it.

Flags:
  --only a,b     update only these plugins
  --yes          download missing tool images without asking
  --no-install   do not download missing tool images
`

func update(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("update", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	only := fl.String("only", "", "")
	yes := fl.Bool("yes", false, "")
	noInstall := fl.Bool("no-install", false, "")
	if err := fl.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, updateUsage)
		return exitOK
	} else if err != nil || fl.NArg() != 0 || *yes && *noInstall {
		fmt.Fprint(stderr, updateUsage)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit update: %v\n", err)
		return exitInvalid
	}
	all, err := plugins.Builtin()
	if err != nil {
		return fail(err)
	}
	var withData []*manifest.Manifest
	for _, m := range all {
		if m.Data != nil {
			withData = append(withData, m)
		}
	}
	selected := withData
	if ids := splitList(*only); len(ids) > 0 {
		selected = nil
		for _, id := range ids {
			i := slices.IndexFunc(withData, func(m *manifest.Manifest) bool { return m.ID == id })
			if i < 0 {
				return fail(fmt.Errorf("plugin %q does not exist or needs no data", id))
			}
			selected = append(selected, withData[i])
		}
	}
	dir, err := dataDir()
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "Updating data for %d plugin(s). This downloads from each tool's publisher.\n", len(selected))
	_, un, fetched, err := prepare(ctx, selected, rootsIn(dir), consent{yes: *yes, none: *noInstall, data: true}, stdout)
	if err != nil {
		return fail(err)
	}
	code := exitOK
	for _, m := range selected {
		switch u, ok := un[m.ID]; {
		case fetched[m.ID]:
			fmt.Fprintf(stdout, "  %-10s updated\n", m.ID)
		case ok:
			fmt.Fprintf(stdout, "  %-10s %s - %s\n", m.ID, u.Status, u.Reason)
			code = exitInvalid
		default:
			fmt.Fprintf(stdout, "  %-10s not updated\n", m.ID)
			code = exitInvalid
		}
	}
	return code
}
