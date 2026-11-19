package checks

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// Unreadable lists the files and directories under root that a process
// running as uid:gid (with no other groups) cannot read, as slash-separated
// paths relative to root. A directory that cannot be listed is reported once
// and not entered. Symlinks and special files are ignored, as the tools do
// not follow them. Every directory is walked, including .git and dependency
// directories, because container tools read them too. The walk stops after
// MaxFiles entries or MaxDepth levels and returns what it found with
// ErrTooManyFiles in the first case.
//
// SiegeKit uses this when it runs as root: tools then run as a fixed
// non-root user and silently miss files only root may read (owner decision,
// 2026-11-19: report them and mark the affected checks incomplete).
func Unreadable(ctx context.Context, root string, uid, gid uint32) ([]string, error) {
	var out []string
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if n++; n > MaxFiles {
			return ErrTooManyFiles
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("file ownership is not available on this system")
		}
		need := fs.FileMode(4) // read
		if d.IsDir() {
			need = 5 // read and search
		}
		if !canAccess(info.Mode().Perm(), st.Uid, st.Gid, uid, gid, need) {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				out = append(out, rel+"/")
				if p == root {
					return filepath.SkipAll
				}
				return filepath.SkipDir
			}
			out = append(out, rel)
			return nil
		}
		if d.IsDir() && p != root {
			rel, _ := filepath.Rel(root, p)
			if strings.Count(filepath.ToSlash(rel), "/") >= MaxDepth {
				return filepath.SkipDir
			}
		}
		return nil
	})
	return out, err
}

// canAccess applies the owner, group and other permission bits in the order
// the kernel does: the first class that applies decides.
func canAccess(perm fs.FileMode, fileUID, fileGID, uid, gid uint32, need fs.FileMode) bool {
	switch {
	case fileUID == uid:
		return perm>>6&need == need
	case fileGID == gid:
		return perm>>3&need == need
	default:
		return perm&need == need
	}
}
