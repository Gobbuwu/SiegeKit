// Package files downloads a plugin's pinned files (ADR 0024): a release
// archive or binary from the publisher's GitHub releases, checked against
// its size and SHA-256 before anything is unpacked, and kept in SiegeKit's
// data directory under the checksum.
package files

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
)

// Limits on what an archive may unpack to.
const (
	MaxUnpacked = 2 << 30 // bytes
	MaxEntries  = 200000
)

// Hosts are the only hosts a download, or a redirect it follows, may reach:
// GitHub, where every pinned file is published, and the hosts GitHub
// redirects release downloads and source archives to.
var Hosts = []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "codeload.github.com"}

// Dir is where the file a is kept under root.
func Dir(root string, a manifest.Artifact) string {
	return filepath.Join(root, a.SHA256)
}

// Installed reports whether a was downloaded and unpacked completely.
func Installed(root string, a manifest.Artifact) bool {
	st, err := os.Lstat(Dir(root, a))
	if err != nil || !st.IsDir() {
		return false
	}
	_, err = os.Lstat(Dir(root, a) + ".ok")
	return err == nil
}

// Client returns the HTTP client for downloads: proxy from the environment,
// redirects only to Hosts over https.
func Client() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return checkURL(req.URL)
		},
	}
}

func checkURL(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || !slices.Contains(Hosts, strings.ToLower(u.Hostname())) || (u.Port() != "" && u.Port() != "443") {
		return fmt.Errorf("download from %s refused: only https from %s", u.Redacted(), strings.Join(Hosts, ", "))
	}
	return nil
}

// Fetch downloads a with c, checks its size and SHA-256, and unpacks it into
// Dir(root, a): an archive (.tar.gz, .tgz or .zip) as its regular files and
// directories, a binary as one executable file named after the URL's last
// path element. Nothing is kept if any check fails.
func Fetch(ctx context.Context, c *http.Client, root string, a manifest.Artifact) error {
	u, err := url.Parse(a.Ref)
	if err != nil {
		return err
	}
	if err := checkURL(u); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Ref, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", a.Ref, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, a.Size+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", a.Ref, err)
	}
	if int64(len(body)) != a.Size {
		return fmt.Errorf("download %s: got %d bytes or more, the pin says %d", a.Ref, len(body), a.Size)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return fmt.Errorf("download %s: SHA-256 %s does not match the pin %s", a.Ref, got, a.SHA256)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(root, ".unpack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := Unpack(body, u.Path, a.Kind, tmp); err != nil {
		return fmt.Errorf("unpack %s: %w", a.Ref, err)
	}
	dst := Dir(root, a)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // #nosec G302 -- read by the container user; root is private
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return os.WriteFile(dst+".ok", []byte(a.Ref+"\n"), 0o600)
}

// Unpack writes body into dir according to kind and the file name in
// urlPath.
func Unpack(body []byte, urlPath, kind, dir string) error {
	name := path.Base(urlPath)
	switch {
	case kind == "binary":
		if !validName(name) {
			return fmt.Errorf("binary name %q is not allowed", name)
		}
		return os.WriteFile(filepath.Join(dir, name), body, 0o755) // #nosec G306 -- an executable the container runs
	case strings.HasSuffix(name, ".zip"):
		return unzip(body, dir)
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return untar(body, dir)
	}
	return fmt.Errorf("%q is not a .tar.gz, .tgz or .zip archive", name)
}

func validName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\\x00")
}

// unpacker writes one archive's entries under dir, refusing anything that
// is not a regular file or directory, any path that leaves dir, and
// archives over the limits.
type unpacker struct {
	dir     string
	total   int64
	entries int
}

func (u *unpacker) target(name string) (string, error) {
	u.entries++
	if u.entries > MaxEntries {
		return "", fmt.Errorf("more than %d entries", MaxEntries)
	}
	n := strings.ReplaceAll(name, "\\", "/")
	c := path.Clean(n)
	if n == "" || strings.Contains(n, "\x00") || path.IsAbs(n) || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("entry %q leaves the archive", name)
	}
	return filepath.Join(u.dir, filepath.FromSlash(c)), nil
}

func (u *unpacker) file(name string, exec bool, r io.Reader) error {
	dst, err := u.target(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- read by the container user; root is private
		return err
	}
	perm := os.FileMode(0o644)
	if exec {
		perm = 0o755
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm) // #nosec G304 -- path checked to stay under dir
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxUnpacked-u.total+1))
	u.total += n
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if u.total > MaxUnpacked {
		return fmt.Errorf("unpacks to more than %d bytes", MaxUnpacked)
	}
	return nil
}

func (u *unpacker) mkdir(name string) error {
	dst, err := u.target(name)
	if err != nil {
		return err
	}
	return os.MkdirAll(dst, 0o755) // #nosec G301 -- read by the container user; root is private
}

func untar(body []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	u := &unpacker{dir: dir}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeReg:
			err = u.file(h.Name, h.Mode&0o111 != 0, tr)
		case tar.TypeDir:
			err = u.mkdir(h.Name)
		case tar.TypeXGlobalHeader:
			continue // GitHub's source archives carry the commit here
		default:
			err = fmt.Errorf("entry %q is not a regular file or directory", h.Name)
		}
		if err != nil {
			return err
		}
	}
}

func unzip(body []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	u := &unpacker{dir: dir}
	for _, f := range zr.File {
		m := f.Mode()
		switch {
		case m.IsDir():
			err = u.mkdir(f.Name)
		case m.IsRegular():
			var rc io.ReadCloser
			if rc, err = f.Open(); err == nil {
				err = u.file(f.Name, m&0o111 != 0, rc)
				if cerr := rc.Close(); err == nil {
					err = cerr
				}
			}
		default:
			err = fmt.Errorf("entry %q is not a regular file or directory", f.Name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
