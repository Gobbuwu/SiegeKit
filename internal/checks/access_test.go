package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCanAccess(t *testing.T) {
	const me, other = 65532, 1000
	for _, tc := range []struct {
		perm             fs.FileMode
		fileUID, fileGID uint32
		need             fs.FileMode
		want             bool
	}{
		{0o644, other, other, 4, true},
		{0o600, other, other, 4, false},
		{0o640, other, me, 4, true},
		{0o004, me, other, 4, false}, // the owner class decides, even if "other" may read
		{0o400, me, me, 4, true},
		{0o711, other, other, 5, false}, // a directory needs read and search
		{0o755, other, other, 5, true},
		{0o750, other, other, 5, false},
	} {
		if got := canAccess(tc.perm, tc.fileUID, tc.fileGID, me, me, tc.need); got != tc.want {
			t.Errorf("canAccess(%o, uid %d, gid %d, need %o) = %v, want %v", tc.perm, tc.fileUID, tc.fileGID, tc.need, got, tc.want)
		}
	}
}

func TestUnreadable(t *testing.T) {
	root := t.TempDir()
	write := func(p string, mode fs.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil { // umask aside
			t.Fatal(err)
		}
	}
	write("ok.py", 0o644)
	write("secret.env", 0o600)
	write(".git/objects/ab/cd", 0o444)
	write("private/inner.py", 0o644)
	if err := os.Chmod(filepath.Join(root, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// Files belong to the test's own user; check them as a different one.
	uid, gid := uint32(os.Getuid()+1), uint32(os.Getgid()+1)
	got, err := Unreadable(context.Background(), root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"private/", "secret.env"}; !slices.Equal(got, want) {
		t.Errorf("Unreadable = %q, want %q", got, want)
	}
	// As the owner, everything is readable.
	got, err = Unreadable(context.Background(), root, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil || len(got) != 0 {
		t.Errorf("as owner: %q, %v", got, err)
	}
}
