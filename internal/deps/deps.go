// Package deps finds what each plugin needs (a pinned tool image and, for
// some, downloaded data), asks the user before installing anything, and says
// which tests cannot run without it (ADR 0016). Some plugins also need
// pinned files from the publisher's GitHub releases (ADR 0024).
package deps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/gomod"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// Engine checks for and downloads pinned images. *sandbox.Engine implements it.
type Engine interface {
	HasImage(ctx context.Context, image string) (bool, error)
	Pull(ctx context.Context, image string) error
}

// Sizer returns an image's download size. *registry.Client implements it.
type Sizer interface {
	DownloadSize(ctx context.Context, image, arch string) (int64, error)
}

// Kinds of dependency.
const (
	Image = "image"
	Data  = "data"
	File  = "file" // a pinned archive or binary (ADR 0024)
	// GoModules are the scanned repository's Go modules, for plugins with
	// run.goModules (ADR 0066).
	GoModules = "go-modules"
)

// Roots are where downloaded data (ADR 0014) and pinned files (ADR 0024)
// are kept; "" means unknown.
type Roots struct {
	Data  string
	Files string
	// Target is the scanned directory, whose Go modules can be
	// downloaded (ADR 0066); "" for none.
	Target string
	// Egress is the person's proxy and extra CA certificate for the
	// containers that use the network (ADR 0066).
	Egress sandbox.Egress
}

// FetchFile downloads one pinned file; a variable so tests can replace it.
var FetchFile = defaultFetchFile

func defaultFetchFile(ctx context.Context, root string, a manifest.Artifact) error {
	return files.Fetch(ctx, files.Client(), root, a)
}

// Dep is one dependency of one plugin.
type Dep struct {
	Kind      string
	Plugin    *manifest.Manifest
	Image     string            // the pinned image (Kind Image), or the image the data update needs (Kind Data)
	Artifact  manifest.Artifact // the pinned file (Kind File)
	Installed bool
	Size      int64  // download size in bytes; -1 if not known
	HostPath  string // a tool of the same name on PATH, which SiegeKit never uses
	// Users are all the plugins that need this image (Plugin is the first);
	// one image is downloaded once even when several plugins use it.
	Users []*manifest.Manifest
	// Go is what was read of the target's Go modules (Kind GoModules).
	Go *gomod.Tree
}

func (d Dep) users() []*manifest.Manifest {
	if len(d.Users) == 0 {
		return []*manifest.Manifest{d.Plugin}
	}
	return d.Users
}

// key identifies d: one image, one plugin's data, or one file.
func (d Dep) key() string {
	switch d.Kind {
	case Image:
		return Image + " " + d.Image
	case File:
		return File + " " + d.Artifact.SHA256
	}
	return d.Kind + " " + d.Plugin.ID
}

// NeededBy lists the IDs of the plugins that need d.
func (d Dep) NeededBy() string {
	ids := make([]string, 0, len(d.users()))
	for _, m := range d.users() {
		ids = append(ids, m.ID)
	}
	return strings.Join(ids, ", ")
}

// RelayID is the Plugin ID of the relay image dependency, which every
// active plugin needs (ADR 0019, ADR 0021).
const RelayID = "siegekit-relay"

// Name is how the dependency is shown to the user.
func (d Dep) Name() string {
	if d.Plugin.ID == RelayID {
		return fmt.Sprintf("%s %s container image (runs SiegeKit's relay for web tests)", d.Plugin.Tool.Name, d.Plugin.Tool.Version)
	}
	if d.Kind == Data {
		return d.Plugin.Tool.Name + " data"
	}
	if d.Kind == File {
		return fmt.Sprintf("%s %s file %s", d.Plugin.Tool.Name, d.Plugin.Tool.Version, path.Base(d.Artifact.Ref))
	}
	if d.Kind == GoModules {
		noun := "modules"
		if d.Go.Required == 1 {
			noun = "module"
		}
		return fmt.Sprintf("Go modules for %s: %d %s named in your go.mod files, from proxy.golang.org, which sees their names and versions", d.NeededBy(), d.Go.Required, noun)
	}
	return fmt.Sprintf("%s %s container image", d.Plugin.Tool.Name, d.Plugin.Tool.Version)
}

// LookPath finds host tools; a variable so tests can replace it.
var LookPath = defaultLookPath

var defaultLookPath = exec.LookPath

// Plan lists the dependencies of each plugin in ms. Data counts as installed
// when its directory and update stamp exist under roots.Data (ADR 0014). An
// image counts as installed only when the engine holds the exact pinned
// digest, and a file only when it was checked and unpacked under
// roots.Files (ADR 0024). An error means the engine itself is not working.
func Plan(ctx context.Context, eng Engine, ms []*manifest.Manifest, roots Roots) ([]Dep, error) {
	var out []Dep
	for _, m := range ms {
		image, ok := runner.ImageFor(m)
		if !ok {
			continue // reported by the runner as having no image for this machine
		}
		if i := slices.IndexFunc(out, func(d Dep) bool { return d.Kind == Image && d.Image == image }); i >= 0 {
			out[i].Users = append(out[i].Users, m)
		} else {
			has, err := eng.HasImage(ctx, image)
			if err != nil {
				return nil, err
			}
			d := Dep{Kind: Image, Plugin: m, Image: image, Installed: has, Size: -1, Users: []*manifest.Manifest{m}}
			if !has {
				if p, err := LookPath(m.Tool.Name); err == nil {
					d.HostPath = p
				}
			}
			out = append(out, d)
		}
		for _, a := range runner.FilesFor(m) {
			if i := slices.IndexFunc(out, func(d Dep) bool { return d.Kind == File && d.Artifact.SHA256 == a.SHA256 }); i >= 0 {
				out[i].Users = append(out[i].Users, m)
				continue
			}
			installed := roots.Files != "" && files.Installed(roots.Files, a)
			out = append(out, Dep{Kind: File, Plugin: m, Artifact: a, Installed: installed, Size: a.Size, Users: []*manifest.Manifest{m}})
		}
		if m.Data != nil {
			out = append(out, Dep{Kind: Data, Plugin: m, Image: image, Installed: dataInstalled(roots.Data, m.ID), Size: -1})
		}
	}
	// Active plugins reach the target through the relay container, which
	// runs in a pinned image of its own.
	var active []*manifest.Manifest
	for _, m := range ms {
		if _, ok := runner.ImageFor(m); ok && m.Network == "target-only" {
			active = append(active, m)
		}
	}
	if len(active) > 0 {
		has, err := eng.HasImage(ctx, sandbox.RelayImage)
		if err != nil {
			return nil, err
		}
		relay := &manifest.Manifest{ID: RelayID, Tool: &manifest.Tool{Name: "alpine", Version: sandbox.RelayImageVersion}}
		out = append(out, Dep{Kind: Image, Plugin: relay, Image: sandbox.RelayImage, Installed: has, Size: -1, Users: active})
	}
	return out, nil
}

// PlanGo adds the target's Go modules to deps, which Plan returned, for
// the plugins in ms with run.goModules (ADR 0066). They count as installed
// when the shared module cache already holds every module, which a check
// with no network finds; that needs the plugin's image. A target with no
// go.mod adds nothing. Module files that cannot be read are an error.
func PlanGo(ctx context.Context, ex runner.Executor, deps []Dep, ms []*manifest.Manifest, roots Roots) ([]Dep, error) {
	var users []*manifest.Manifest
	for _, m := range ms {
		if _, ok := runner.ImageFor(m); ok && m.Run.GoModules && roots.Target != "" {
			users = append(users, m)
		}
	}
	if len(users) == 0 {
		return deps, nil
	}
	t, err := gomod.Find(ctx, roots.Target)
	if err != nil {
		return deps, fmt.Errorf("read the Go module files: %w", err)
	}
	if len(t.Dirs) == 0 {
		return deps, nil
	}
	d := Dep{Kind: GoModules, Plugin: users[0], Users: users, Go: t, Size: -1}
	// One check is enough: the cache is shared, and every such plugin
	// downloads the same modules.
	m := users[0]
	image, _ := runner.ImageFor(m)
	if slices.ContainsFunc(deps, func(x Dep) bool { return x.Kind == Image && x.Image == image && x.Installed }) && roots.Data != "" {
		d.Installed, err = gomod.Present(ctx, ex, t, goJob(m, roots))
		if err != nil {
			return deps, fmt.Errorf("check the Go module cache: %w", err)
		}
	}
	return append(deps, d), nil
}

// goJob is how m's image downloads modules into the cache under roots.
func goJob(m *manifest.Manifest, roots Roots) gomod.Job {
	image, _ := runner.ImageFor(m)
	return gomod.Job{
		Image: image, CPUs: min(m.Resources.CPUs, runtime.NumCPU()), MemoryMiB: m.Resources.MemoryMiB,
		Timeout:  time.Duration(m.Resources.TimeoutSeconds) * time.Second,
		DataRoot: roots.Data, Egress: roots.Egress, Private: gomod.PrivateEnv(os.Getenv),
	}
}

func dataInstalled(root, id string) bool {
	if root == "" {
		return false
	}
	st, err := os.Lstat(filepath.Join(root, id))
	if err != nil || !st.IsDir() {
		return false
	}
	_, err = os.Lstat(filepath.Join(root, id+".updated"))
	return err == nil
}

// AddSizes fills in the download size of each missing image. Sizes that
// cannot be read (no network) stay -1.
func AddSizes(ctx context.Context, s Sizer, deps []Dep) {
	for i, d := range deps {
		if d.Kind == Image && !d.Installed {
			if n, err := s.DownloadSize(ctx, d.Image, runtime.GOARCH); err == nil {
				deps[i].Size = n
			}
		}
	}
}

// Missing returns the dependencies that are not installed.
func Missing(deps []Dep) []Dep {
	var out []Dep
	for _, d := range deps {
		if !d.Installed {
			out = append(out, d)
		}
	}
	return out
}

// Describe writes what is installed, what is missing and which tests need it.
func Describe(w io.Writer, deps []Dep) {
	var have []string
	for _, d := range deps {
		switch {
		case d.Installed && d.Kind == GoModules:
			have = append(have, "Go modules for "+d.NeededBy()+" (in SiegeKit's module cache)")
		case d.Installed:
			have = append(have, d.Name())
		}
	}
	if len(have) > 0 {
		fmt.Fprintf(w, "Already installed (not downloaded again): %s.\n", strings.Join(have, ", "))
	}
	missing := Missing(deps)
	if len(missing) == 0 {
		return
	}
	fmt.Fprintln(w, "Missing dependencies:")
	for i, d := range missing {
		size := "size not known in advance"
		if (d.Kind == Image || d.Kind == File) && d.Size >= 0 {
			size = humanSize(d.Size) + " download"
		}
		fmt.Fprintf(w, "  %d. %s (%s), needed by: %s\n", i+1, d.Name(), size, d.NeededBy())
		if d.HostPath != "" {
			fmt.Fprintf(w, "     %s was found on your system at %s, but SiegeKit uses its own sandboxed, pinned copy.\n", d.Plugin.Tool.Name, d.HostPath)
		}
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", (n+1023)/1024)
	}
}

// Ask reads which of missing (numbered from 1, as Describe prints them) to
// install: "a"/"all", "n"/"none" (or an empty answer), or numbers such as
// "1,3". An invalid answer is asked again, at most three times, then counts
// as none.
func Ask(in io.Reader, out io.Writer, missing []Dep) []Dep {
	r := bufio.NewReader(in)
	for range 3 {
		fmt.Fprint(out, "Install which? [a]ll, [n]one, or numbers such as 1,3: ")
		line, err := r.ReadString('\n')
		if err != nil {
			fmt.Fprintln(out) // the answer's newline was not echoed
		}
		chosen, ok := parseAnswer(strings.TrimSpace(line), missing)
		if ok {
			return chosen
		}
		if err != nil { // end of input
			return nil
		}
		fmt.Fprintln(out, "Please answer a, n, or numbers from the list.")
	}
	return nil
}

func parseAnswer(a string, missing []Dep) ([]Dep, bool) {
	switch strings.ToLower(a) {
	case "a", "all", "y", "yes":
		return missing, true
	case "", "n", "no", "none":
		return nil, true
	}
	var out []Dep
	for _, f := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > len(missing) {
			return nil, false
		}
		if d := missing[n-1]; !slices.ContainsFunc(out, func(x Dep) bool { return x.key() == d.key() }) {
			out = append(out, d)
		}
	}
	return out, true
}

// Install downloads the chosen images, files, data and Go modules. Data
// and Go modules need their plugin's image, so they are not downloaded
// while the image or files are still missing. It returns the plugins that
// cannot run, with the reason, and notes for plugins that run without
// their Go modules (runner.Options.Notes); notChosen gives the outcome of
// a plugin whose dependency was not chosen. A plugin still runs without
// its Go modules (ADR 0066): it then reports the packages it could not
// load.
func Install(ctx context.Context, eng Engine, ex runner.Executor, deps, chosen []Dep, roots Roots, notChosen func(Dep) runner.Unavailable, out io.Writer) (map[string]runner.Unavailable, map[string]string, error) {
	pick := func(d Dep) bool {
		return slices.ContainsFunc(chosen, func(c Dep) bool { return c.key() == d.key() })
	}
	un := map[string]runner.Unavailable{}
	hasImage := map[string]bool{}
	for _, d := range deps {
		if d.Kind != Image {
			continue
		}
		switch {
		case d.Installed:
			for _, m := range d.users() {
				hasImage[m.ID] = true
			}
		case !pick(d):
			for _, m := range d.users() {
				un[m.ID] = notChosen(d)
			}
		default:
			fmt.Fprintf(out, "Downloading %s...\n", d.Name())
			if err := eng.Pull(ctx, d.Image); err != nil {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
				for _, m := range d.users() {
					un[m.ID] = runner.Fail(report.CauseMissingDependency, fmt.Sprintf("could not install %s: %v", d.Name(), err))
				}
				continue
			}
			for _, m := range d.users() {
				hasImage[m.ID] = true
			}
		}
	}
	// A plugin keeps the first reason it cannot run.
	mark := func(d Dep, u runner.Unavailable) {
		for _, m := range d.users() {
			if _, done := un[m.ID]; !done {
				un[m.ID] = u
			}
		}
	}
	for _, d := range deps {
		if d.Kind != File || d.Installed {
			continue
		}
		if !pick(d) {
			mark(d, notChosen(d))
			continue
		}
		if roots.Files == "" {
			return nil, nil, errors.New("cannot find a directory for downloaded files")
		}
		fmt.Fprintf(out, "Downloading %s...\n", d.Name())
		if err := FetchFile(ctx, roots.Files, d.Artifact); err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			mark(d, runner.Fail(report.CauseMissingDependency, fmt.Sprintf("could not install %s: %v", d.Name(), err)))
		}
	}
	var update []*manifest.Manifest
	for _, d := range deps {
		if d.Kind != Data || d.Installed {
			continue
		}
		if _, done := un[d.Plugin.ID]; done {
			continue // its image or a file is missing; already reported
		}
		if !pick(d) {
			un[d.Plugin.ID] = notChosen(d)
			continue
		}
		update = append(update, d.Plugin)
	}
	if len(update) > 0 {
		if roots.Data == "" {
			return nil, nil, errors.New("cannot find a directory for downloaded data")
		}
		fmt.Fprintln(out, "Downloading tool data (network access, none of your files).")
		results, err := runner.Update(ctx, ex, update, roots.Data, "", roots.Egress)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range results {
			if r.Err != nil {
				un[r.ID] = runner.Fail(report.CauseMissingDependency, fmt.Sprintf("could not download data: %v", r.Err))
			}
		}
	}
	notes := map[string]string{}
	for _, d := range deps {
		if d.Kind != GoModules || d.Installed {
			continue
		}
		note := ""
		switch _, done := un[d.Plugin.ID]; {
		case done:
			continue // its image or a file is missing; already reported
		case !pick(d):
			note = "The Go module download was not done: " + notChosen(d).Reason + "."
		case roots.Data == "":
			return nil, nil, errors.New("cannot find a directory for downloaded data")
		default:
			fmt.Fprintf(out, "Downloading %s (network access, only copies of your go.mod, go.sum, go.work and go.work.sum files)...\n", d.Name())
			if err := gomod.Download(ctx, ex, d.Go, goJob(d.Plugin, roots)); err != nil {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
				fmt.Fprintf(out, "Could not download every Go module: %v\n", err)
				note = "The Go module download did not complete: " + err.Error() + "."
			}
		}
		if note != "" {
			for _, m := range d.users() {
				notes[m.ID] = note
			}
		}
	}
	return un, notes, nil
}

// NoEngine marks every plugin as skipped because no container engine was
// found.
func NoEngine(ms []*manifest.Manifest, reason string) map[string]runner.Unavailable {
	un := map[string]runner.Unavailable{}
	for _, m := range ms {
		un[m.ID] = runner.Skip(report.CauseMissingDependency, reason)
	}
	return un
}

// EngineHelp is printed when no container engine is found.
func EngineHelp(goos string) string {
	steps := "Install Docker Engine (https://docs.docker.com/engine/install/) or Podman (https://podman.io/docs/installation) with your package manager."
	if goos == "darwin" {
		steps = "Install Docker Desktop (https://docs.docker.com/desktop/setup/install/mac-install/) or Podman (https://podman.io/docs/installation), then start it."
	}
	return "No container engine (Docker or Podman) was found, so only SiegeKit's built-in checks can run. SiegeKit does not install one for you: it needs administrator rights. " + steps
}
