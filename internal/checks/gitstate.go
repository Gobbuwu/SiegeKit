package checks

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- git's index checksum, not a security use
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// GitIgnoredNote ends the message of a finding in a file that git ignores
// and does not track (ADR 0068).
const GitIgnoredNote = "This file is git-ignored: not committed."

// maxIndexSize bounds the git index SiegeKit reads. An index lists about
// 100 bytes per tracked file, so this is over two million files.
const maxIndexSize = 256 << 20

// GitState answers whether files of a repository are ignored by git and
// not tracked by it (ADR 0068). It says so only when it knows: for a
// target that is not a git repository with a .git directory, or whose
// index it cannot read in full, every answer is false.
type GitState struct {
	ig      *ignores
	tracked map[string]bool
	dirs    []string // sparse-index directory entries, each ending in "/"
}

// NewGitState reads the repository at root: its .gitignore files and
// .git/info/exclude (with the dotenv check's matcher) and its index.
func NewGitState(root string) *GitState {
	gitDir := filepath.Join(root, ".git")
	if st, err := os.Lstat(gitDir); err != nil || !st.IsDir() {
		return &GitState{}
	}
	hashLen, err := gitHashLen(gitDir)
	if err != nil {
		return &GitState{}
	}
	data, err := readIndexFile(filepath.Join(gitDir, "index"))
	if err != nil {
		return &GitState{}
	}
	g := &GitState{ig: &ignores{root: root, cache: map[string][]ignoreRule{}}, tracked: map[string]bool{}}
	if data == nil {
		return g // no index yet: nothing is tracked
	}
	names, err := parseIndex(data, hashLen)
	if err != nil {
		return &GitState{}
	}
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			g.dirs = append(g.dirs, n)
		} else {
			g.tracked[n] = true
		}
	}
	return g
}

// IgnoredUntracked reports whether the file at rel (slash-separated, relative
// to the repository's top level) is ignored by git and not in its index.
func (g *GitState) IgnoredUntracked(rel string) bool {
	if g.ig == nil || !filepath.IsLocal(filepath.FromSlash(rel)) || g.tracked[rel] {
		return false
	}
	for _, d := range g.dirs {
		if strings.HasPrefix(rel, d) {
			return false
		}
	}
	return g.ig.ignored(rel)
}

// gitHashLen returns the length of the repository's object IDs: 32 bytes
// when .git/config sets extensions.objectFormat to sha256, else 20.
func gitHashLen(gitDir string) (int, error) {
	data, err := readFile(filepath.Join(gitDir, "config"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	section, n := "", 20
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] \t")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && section == "extensions" && strings.TrimSpace(k) == "objectformat" {
			switch strings.Trim(strings.TrimSpace(v), `"`) {
			case "sha1":
				n = 20
			case "sha256":
				n = 32
			default:
				return 0, fmt.Errorf("unknown object format %q", v)
			}
		}
	}
	return n, nil
}

// readIndexFile reads the index without following symlinks. A missing
// index returns nil and no error.
func readIndexFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the target's own git index; symlinks refused, size limited
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxIndexSize {
		return nil, errors.New("index is not a regular file of a readable size")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIndexSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIndexSize {
		return nil, errors.New("index too large")
	}
	return data, nil
}

// parseIndex returns the path of every entry of a git index, versions 2 to
// 4 (git's Documentation/gitformat-index.txt). A sparse index's directory
// entries end in "/". The file is untrusted: every length is checked, the
// entries must be sorted and fill the file up to its extensions, and the
// trailing checksum must match (or be zero, as git writes it with
// index.skipHash). A split index (the "link" extension) keeps entries in
// another file, so it is an error.
func parseIndex(data []byte, hashLen int) ([]string, error) {
	bad := func(why string) ([]string, error) { return nil, errors.New("git index: " + why) }
	if len(data) < 12+hashLen || string(data[:4]) != "DIRC" {
		return bad("no header")
	}
	body, sum := data[:len(data)-hashLen], data[len(data)-hashLen:]
	if !bytes.Equal(sum, make([]byte, hashLen)) {
		var h hash.Hash = sha1.New() // #nosec G401 -- git's index checksum
		if hashLen == 32 {
			h = sha256.New()
		}
		h.Write(body)
		if !bytes.Equal(h.Sum(nil), sum) {
			return bad("checksum mismatch")
		}
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version < 2 || version > 4 {
		return bad(fmt.Sprintf("version %d", version))
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if uint64(count) > uint64(len(body)) {
		return bad("entry count larger than the file")
	}
	names := make([]string, 0, count)
	off, prev := 12, ""
	for range count {
		fixed := 40 + hashLen + 2
		if off+fixed > len(body) {
			return bad("entry past the end")
		}
		mode := binary.BigEndian.Uint32(body[off+24 : off+28])
		flags := binary.BigEndian.Uint16(body[off+40+hashLen : off+fixed])
		p := off + fixed
		if flags&0x4000 != 0 {
			if version < 3 {
				return bad("extended flags in a version 2 index")
			}
			p += 2
		}
		var name string
		if version == 4 {
			strip, n := indexVarint(body[min(p, len(body)):])
			if n == 0 || strip > len(prev) {
				return bad("bad path prefix")
			}
			p += n
			end := bytes.IndexByte(body[min(p, len(body)):], 0)
			if end < 0 {
				return bad("unterminated path")
			}
			name = prev[:len(prev)-strip] + string(body[p:p+end])
			off = p + end + 1
		} else {
			end := bytes.IndexByte(body[min(p, len(body)):], 0)
			if end < 0 {
				return bad("unterminated path")
			}
			if l := int(flags & 0x0fff); l < 0x0fff && l != end {
				return bad("path length mismatch")
			}
			name = string(body[p : p+end])
			off += (p - off + end + 8) &^ 7
		}
		if name == "" || name < prev {
			return bad("entries out of order")
		}
		if mode&0o170000 == 0o040000 && !strings.HasSuffix(name, "/") {
			return bad("directory entry without a trailing slash")
		}
		names = append(names, name)
		prev = name
	}
	for off < len(body) {
		if off+8 > len(body) {
			return bad("extension past the end")
		}
		sig := string(body[off : off+4])
		// Read byte by byte: the size is at most 2^32-1, so it fits an int
		// on the 64-bit platforms SiegeKit is built for, with no conversion
		// that could wrap.
		size := int(body[off+4])<<24 | int(body[off+5])<<16 | int(body[off+6])<<8 | int(body[off+7])
		if sig == "link" {
			return bad("split index")
		}
		if size > len(body)-off-8 {
			return bad("extension past the end")
		}
		off += 8 + size
	}
	if off != len(body) {
		return bad("entries past the end")
	}
	return names, nil
}

// indexVarint decodes git's offset varint (varint.c), returning the value
// and the bytes read, or 0 bytes when b holds no complete value or one
// larger than an index can hold.
func indexVarint(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	v := int(c & 0x7f)
	n := 1
	for c&0x80 != 0 {
		if n >= len(b) || v > maxIndexSize {
			return 0, 0
		}
		c = b[n]
		n++
		v = ((v + 1) << 7) | int(c&0x7f)
	}
	return v, n
}
