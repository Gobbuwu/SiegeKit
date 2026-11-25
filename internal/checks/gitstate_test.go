package checks

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The fixtures are indexes git 2.43.0 wrote (testdata/gitindex/make.sh).
func readIndexFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "gitindex", "index-"+name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseIndex(t *testing.T) {
	files := []string{".env.local", ".gitignore", "a.txt", "dir/b.txt", "dir/sub/c.txt"}
	for _, c := range []struct {
		name    string
		hashLen int
		want    []string
	}{
		{"v2", 20, files},
		{"v3", 20, append(slices.Clone(files), "new.txt")}, // intent-to-add: extended flags
		{"v4", 20, files}, // path prefix compression
		{"sha256", 32, files},
		{"skiphash", 20, files}, // zero checksum
		{"sparse", 20, []string{".env.local", ".gitignore", "a.txt", "dir/"}},
	} {
		got, err := parseIndex(readIndexFixture(t, c.name), c.hashLen)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: %q %v, want %q", c.name, got, err, c.want)
		}
	}
	// A split index keeps entries in another file: not readable here.
	if got, err := parseIndex(readIndexFixture(t, "split"), 20); err == nil {
		t.Errorf("split index read as %q", got)
	}
	// The wrong object format fails the checksum.
	if _, err := parseIndex(readIndexFixture(t, "sha256"), 20); err == nil {
		t.Error("sha256 index read with sha1 IDs")
	}
	if _, err := parseIndex(readIndexFixture(t, "v2"), 32); err == nil {
		t.Error("sha1 index read with sha256 IDs")
	}
}

// A damaged index is an error, never a shorter list of tracked files.
func TestParseIndexDamaged(t *testing.T) {
	v2 := readIndexFixture(t, "v2")
	flipped := slices.Clone(v2)
	flipped[100] ^= 1
	if _, err := parseIndex(flipped, 20); err == nil {
		t.Error("checksum not checked")
	}
	for _, name := range []string{"skiphash", "v4"} {
		b := readIndexFixture(t, name)
		if name == "v4" {
			copy(b[len(b)-20:], make([]byte, 20)) // as with index.skipHash
		}
		for n := 12; n < len(b)-20; n++ {
			cut := append(slices.Clone(b[:n]), make([]byte, 20)...)
			if got, err := parseIndex(cut, 20); err == nil && len(got) < 5 {
				t.Errorf("%s cut at %d: %q", name, n, got)
			}
		}
		more := slices.Clone(b)
		binary.BigEndian.PutUint32(more[8:12], binary.BigEndian.Uint32(more[8:12])+1)
		if _, err := parseIndex(more, 20); err == nil {
			t.Errorf("%s: entry count larger than the entries", name)
		}
	}
	for _, b := range [][]byte{nil, []byte("DIRC"), append([]byte("DIRX\x00\x00\x00\x02\x00\x00\x00\x00"), make([]byte, 20)...), append([]byte("DIRC\x00\x00\x00\x05\x00\x00\x00\x00"), make([]byte, 20)...)} {
		if _, err := parseIndex(b, 20); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
}

func FuzzParseIndex(f *testing.F) {
	for _, n := range []string{"v2", "v3", "v4", "skiphash", "sparse", "split"} {
		b, err := os.ReadFile(filepath.Join("testdata", "gitindex", "index-"+n))
		if err != nil {
			f.Fatal(err)
		}
		copy(b[len(b)-20:], make([]byte, 20)) // so that mutations reach the parser
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseIndex(b, 20)
		_, _ = parseIndex(b, 32)
	})
}

// gitRepo makes a repository with .gitignore ".env*.local" and the given
// index fixture ("" for none) and .git/config.
func gitRepo(t *testing.T, index, config string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p string, b []byte) {
		if err := os.WriteFile(filepath.Join(root, p), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", []byte(".env*.local\n"))
	if index != "" {
		write(".git/index", readIndexFixture(t, index))
	}
	if config != "" {
		write(".git/config", []byte(config))
	}
	return root
}

func TestGitStateIgnoredUntracked(t *testing.T) {
	sha256Config := "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat = sha256\n"
	for _, c := range []struct {
		name, index, config string
		want                map[string]bool
	}{
		// .env.local is ignored but tracked (git add -f): it is committed.
		{"v2", "v2", "", map[string]bool{".env.local": false, ".env.dev.local": true, "dir/.env.local": true, "a.txt": false, "new.txt": false, "../.env.local": false, "/.env.local": false}},
		{"v4", "v4", "", map[string]bool{".env.local": false, ".env.dev.local": true}},
		{"sha256", "sha256", sha256Config, map[string]bool{".env.local": false, ".env.dev.local": true}},
		// A sparse directory entry stands for every file under it.
		{"sparse", "sparse", "", map[string]bool{"dir/.env.local": false, ".env.dev.local": true}},
		{"no index yet", "", "", map[string]bool{".env.local": true, "a.txt": false}},
		// Not known: no answer is true.
		{"sha256 index, sha1 config", "sha256", "", map[string]bool{".env.dev.local": false}},
		{"split index", "split", "", map[string]bool{".env.dev.local": false}},
		{"unknown object format", "v2", "[extensions]\nobjectformat = sha3\n", map[string]bool{".env.dev.local": false}},
	} {
		g := NewGitState(gitRepo(t, c.index, c.config))
		for rel, want := range c.want {
			if got := g.IgnoredUntracked(rel); got != want {
				t.Errorf("%s: %s = %v, want %v", c.name, rel, got, want)
			}
		}
	}
	// .env.local in the v2 index is ignored by the matcher: only the index
	// tells that it is committed.
	root := gitRepo(t, "v2", "")
	if ig := (&ignores{root: root, cache: map[string][]ignoreRule{}}); !ig.ignored(".env.local") {
		t.Error("matcher does not ignore .env.local")
	}
	// Not a repository, or .git is a file (a worktree or submodule).
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, ".gitignore"), []byte(".env*.local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if NewGitState(plain).IgnoredUntracked(".env.local") {
		t.Error("no repository")
	}
	if err := os.WriteFile(filepath.Join(plain, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if NewGitState(plain).IgnoredUntracked(".env.local") {
		t.Error(".git file")
	}
	// A symlinked index is not followed.
	linked := gitRepo(t, "", "")
	if err := os.Symlink(filepath.Join("testdata", "gitindex", "index-v2"), filepath.Join(linked, ".git", "index")); err != nil {
		t.Fatal(err)
	}
	if NewGitState(linked).IgnoredUntracked(".env.dev.local") {
		t.Error("symlinked index followed or treated as no index")
	}
}
