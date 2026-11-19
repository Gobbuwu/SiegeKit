package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// MaxDataSize caps what one data update may leave on disk.
const MaxDataSize int64 = 8 << 30

// stampName is the file, next to the data directory, that records when
// SiegeKit last updated it. The tool cannot write it: it lives outside the
// directory mounted into the update container.
func stampName(root, id string) string { return filepath.Join(root, id+".updated") }

// dataFor returns the data directory for m and a warning if the data is old.
func dataFor(root string, m *manifest.Manifest, now time.Time) (dir, warning string, err error) {
	if root == "" {
		return "", "", errors.New("no data directory configured")
	}
	dir = filepath.Join(root, m.ID)
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("no %s data yet: run 'siegekit update' first", m.Tool.Name)
	}
	if err != nil {
		return "", "", err
	}
	if !st.IsDir() {
		return "", "", fmt.Errorf("%s is not a directory", dir)
	}
	b, err := os.ReadFile(stampName(root, m.ID))
	if err != nil {
		return dir, "data age unknown; run 'siegekit update'", nil
	}
	updated, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return dir, "data age unknown; run 'siegekit update'", nil
	}
	if days := int(now.Sub(updated).Hours() / 24); days > m.Data.MaxAgeDays {
		warning = fmt.Sprintf("data is %d days old; run 'siegekit update'", days)
	}
	return dir, warning, nil
}

// UpdateResult is the outcome of updating one plugin's data.
type UpdateResult struct {
	ID  string
	Err error
}

// Update downloads data for each selected plugin that declares a data
// section (ADR 0014). Each update runs in its own container with network
// access but no target or user files mounted. New data replaces the old only
// after the update succeeds, so a failed update leaves the previous data.
func Update(ctx context.Context, ex Executor, selected []*manifest.Manifest, root, workDir string) ([]UpdateResult, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("data directory %q must be an absolute path", root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	// The sandbox opens each new data directory to any container user, which
	// is only safe while the parent is private.
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- a directory: owner-only is the strictest useful mode
		return nil, err
	}
	work, err := os.MkdirTemp(workDir, "siegekit-update-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	var out []UpdateResult
	for _, m := range selected {
		if m.Data == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		out = append(out, UpdateResult{ID: m.ID, Err: updateOne(ctx, ex, m, root, work)})
	}
	return out, ctx.Err()
}

func updateOne(ctx context.Context, ex Executor, m *manifest.Manifest, root, work string) error {
	if err := removeLeftovers(root, m.ID); err != nil {
		return err
	}
	image, ok := ImageFor(m)
	if !ok {
		return fmt.Errorf("no container image for linux/%s", runtime.GOARCH)
	}
	cpus := min(m.Resources.CPUs, runtime.NumCPU())
	args := make([]string, len(m.Data.UpdateArgs))
	r := strings.NewReplacer("{data}", m.Data.Mount, "{threads}", strconv.Itoa(cpus))
	for i, a := range m.Data.UpdateArgs {
		args[i] = r.Replace(a)
	}
	fresh, err := os.MkdirTemp(root, "."+m.ID+"-new-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(fresh) // #nosec G104 -- best effort; removeLeftovers retries next time
		}
	}()
	out, err := os.MkdirTemp(work, m.ID+"-")
	if err != nil {
		return err
	}
	res, err := ex.Run(ctx, sandbox.Spec{
		Image: image, Args: args, OutDir: out, Network: "egress",
		DataDir: fresh, DataMount: m.Data.Mount, DataWritable: true,
		CPUs: cpus, MemoryMiB: m.Resources.MemoryMiB,
		// Downloads are staged in /tmp (Trivy keeps two copies of its
		// 134 MiB archive), so updates get half the memory limit there.
		TmpMiB:  m.Resources.MemoryMiB / 2,
		Timeout: time.Duration(m.Resources.TimeoutSeconds) * time.Second,
	})
	switch {
	case err != nil:
		return err
	case res.Status == sandbox.TimedOut:
		return fmt.Errorf("stopped after %d seconds", m.Resources.TimeoutSeconds)
	case res.Status == sandbox.Failed || res.ExitCode != 0:
		return fmt.Errorf("update failed (exit code %d): %s", res.ExitCode, lastLine(res.Stderr))
	}
	size, files, err := treeSize(fresh)
	if err != nil {
		return err
	}
	if files == 0 {
		return errors.New("update wrote no data")
	}
	if size > MaxDataSize {
		return fmt.Errorf("update wrote %d bytes, more than the %d byte limit", size, MaxDataSize)
	}

	// Swap in the new data: move the old directory aside, rename the new one
	// into place, then delete the old one.
	dir := filepath.Join(root, m.ID)
	var old string
	if _, err := os.Lstat(dir); err == nil {
		old = filepath.Join(root, "."+m.ID+"-old-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := os.Rename(dir, old); err != nil {
			return err
		}
	}
	if err := os.Rename(fresh, dir); err != nil {
		if old != "" {
			if rerr := os.Rename(old, dir); rerr != nil {
				return fmt.Errorf("%w; the previous data is in %s and could not be moved back: %v", err, old, rerr)
			}
		}
		return err
	}
	keep = true
	if old != "" {
		// A failure leaves the old copy behind; the next update removes it.
		os.RemoveAll(old) // #nosec G104 -- cleaned up by removeLeftovers
	}
	return writeStamp(root, m.ID, time.Now().UTC())
}

// removeLeftovers deletes the new and old data directories that an
// interrupted or partly failed update left in root, which can be large.
func removeLeftovers(root, id string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() && (strings.HasPrefix(n, "."+id+"-new-") || strings.HasPrefix(n, "."+id+"-old-")) {
			if err := os.RemoveAll(filepath.Join(root, n)); err != nil {
				return fmt.Errorf("remove leftover %s: %w", n, err)
			}
		}
	}
	return nil
}

func writeStamp(root, id string, t time.Time) error {
	tmp, err := os.CreateTemp(root, ".stamp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(t.Format(time.RFC3339) + "\n"); err != nil {
		tmp.Close() // #nosec G104 -- the write error is returned instead
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), stampName(root, id))
}

// treeSize returns the total size and count of regular files under dir,
// without following symlinks.
func treeSize(dir string) (size int64, files int, err error) {
	err = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
			files++
		}
		return nil
	})
	return size, files, err
}
