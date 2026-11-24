package runner

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/gomod"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// goRun is the setup of one run of a plugin with run.goModules (ADR 0066).
type goRun struct {
	scratch    string            // the per-run scratch folder
	env        map[string]string // the plugin's environment plus Go's settings
	cache      string            // the shared module cache, "" when there is none
	cacheMount string
	input      string // what the report says about the module cache
}

// Scratch folder layout, inside sandbox.ScratchMount: Go's build cache and
// its compile scratch ($WORK). Both are created by SiegeKit, so a cleanup
// container can remove them by name.
const (
	scratchCache = "cache"
	scratchTmp   = "tmp"
)

// goSetup makes the scratch folder of one run (ADR 0066, 2B) and mounts
// the module cache under dataRoot read-only when it exists (4A).
//
// The scratch folder is made in dataRoot/scratch, not in the run folder
// under the system's temporary directory: that directory can be a tmpfs
// (RAM), and pages a container writes to a tmpfs, even one bind-mounted
// from the host, count against the container's memory limit (measured:
// a 256 MiB container was killed after writing 254 MiB to a host tmpfs,
// Docker 29.9.3, cgroup v1), which would bring back the limit 2B removes.
// work is used only when there is no data root.
func goSetup(m *manifest.Manifest, dataRoot, work string) (goRun, error) {
	g := goRun{env: maps.Clone(m.Run.Env)}
	if g.env == nil {
		g.env = map[string]string{}
	}
	parent := work
	if dataRoot != "" {
		parent = filepath.Join(dataRoot, "scratch")
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return g, fmt.Errorf("create scratch folder: %w", err)
		}
		// The sandbox opens the scratch folder to any container user,
		// which is only safe while its parent is private.
		if err := os.Chmod(parent, 0o700); err != nil { // #nosec G302 -- a directory: owner-only
			return g, err
		}
	}
	dir, err := os.MkdirTemp(parent, m.ID+"-")
	if err != nil {
		return g, fmt.Errorf("create scratch folder: %w", err)
	}
	g.scratch = dir
	for _, sub := range []string{scratchCache, scratchTmp} {
		p := filepath.Join(dir, sub)
		if err := os.Mkdir(p, 0o700); err != nil {
			return g, fmt.Errorf("create scratch folder: %w", err)
		}
		// The container user may differ from the caller; the run folder
		// is private.
		if err := os.Chmod(p, 0o777); err != nil { // #nosec G302 -- inside SiegeKit's private run folder, as the output folder
			return g, err
		}
	}
	g.env["GOCACHE"] = sandbox.ScratchMount + "/" + scratchCache
	g.env["GOTMPDIR"] = sandbox.ScratchMount + "/" + scratchTmp
	if dataRoot == "" {
		return g, nil
	}
	cache := gomod.CacheDir(dataRoot)
	if st, err := os.Lstat(cache); err != nil || !st.IsDir() {
		return g, nil
	}
	size, err := treeBytes(cache)
	if err != nil {
		return g, fmt.Errorf("read the Go module cache: %w", err)
	}
	g.cache, g.cacheMount = cache, gomod.CacheMount
	g.env["GOMODCACHE"] = gomod.CacheMount
	g.env["GOPROXY"] = "off"
	g.input = fmt.Sprintf("Go modules from SiegeKit's shared module cache, read-only (%s in %s)", humanBytes(size), cache)
	return g, nil
}

// removeScratch deletes a scratch folder. Files the tool wrote can belong
// to a host user other than the caller (rootless engines map the container
// user to a subordinate ID), so what the caller cannot delete is first
// deleted by a container running as the tool's user.
func removeScratch(ex Executor, image, dir string) error {
	if dir == "" || os.RemoveAll(dir) == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := os.MkdirTemp(filepath.Dir(dir), "cleanup-")
	if err == nil {
		defer os.RemoveAll(out)
		var res *sandbox.Result
		res, err = ex.Run(ctx, sandbox.Spec{
			Image: image, Entrypoint: "rm",
			Args:   []string{"-rf", sandbox.ScratchMount + "/" + scratchCache, sandbox.ScratchMount + "/" + scratchTmp},
			OutDir: out, ScratchDir: dir, Network: "none",
			CPUs: 1, MemoryMiB: 256, Timeout: 5 * time.Minute,
		})
		if err == nil && (res.Status != sandbox.Completed || res.ExitCode != 0) {
			err = fmt.Errorf("cleanup container: %s", lastLine(res.Stderr))
		}
	}
	if rerr := os.RemoveAll(dir); rerr != nil {
		if err == nil {
			err = rerr
		}
		return fmt.Errorf("SiegeKit could not delete the tool's scratch folder %s: %v", dir, err)
	}
	return nil
}

// treeBytes is the size of the regular files under dir, without following
// symlinks.
func treeBytes(dir string) (int64, error) {
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			n += fi.Size()
		}
		return nil
	})
	return n, err
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", (n+1023)/1024)
	}
}
