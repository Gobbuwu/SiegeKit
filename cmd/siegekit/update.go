package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

const updateUsage = `Usage: siegekit update [--only a,b]

Downloads the data some checks need, such as vulnerability databases, into
~/.local/share/siegekit/data. Each download runs in a container that has
network access but none of your files. Scans then use the data offline.

Flags:
  --only a,b   update only these plugins
`

func update(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("update", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	only := fl.String("only", "", "")
	if err := fl.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, updateUsage)
		return exitOK
	} else if err != nil || fl.NArg() != 0 {
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
	ex, err := newExecutor()
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "Updating data for %d plugin(s). This downloads from each tool's publisher.\n", len(selected))
	results, err := runner.Update(ctx, ex, selected, filepath.Join(dir, "data"), "")
	if err != nil {
		return fail(err)
	}
	code := exitOK
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(stdout, "  %-10s failed - %v\n", r.ID, r.Err)
			code = exitInvalid
		} else {
			fmt.Fprintf(stdout, "  %-10s updated\n", r.ID)
		}
	}
	return code
}
