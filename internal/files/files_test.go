package files

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
)

type entry struct {
	name string
	typ  byte
	mode int64
	body string
	link string
}

func tgz(t *testing.T, es ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Size: int64(len(e.body)), Linkname: e.link}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func zipOf(t *testing.T, es ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range es {
		h := &zip.FileHeader{Name: e.name}
		mode := os.FileMode(e.mode)
		if e.typ == tar.TypeSymlink {
			mode |= os.ModeSymlink
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body + e.link))
	}
	zw.Close()
	return b.Bytes()
}

func TestUnpack(t *testing.T) {
	good := []entry{{"tool-1.0/", tar.TypeDir, 0o755, "", ""}, {"tool-1.0/bin/tool", tar.TypeReg, 0o755, "#!", ""}, {"tool-1.0/README", tar.TypeReg, 0o600, "hi", ""}}
	for name, tc := range map[string]struct {
		body []byte
		file string
		kind string
		want string // error substring; "" for success
	}{
		"tar.gz":           {tgz(t, good...), "t.tar.gz", "archive", ""},
		"zip":              {zipOf(t, entry{"tool-1.0/bin/tool", tar.TypeReg, 0o755, "#!", ""}, entry{"tool-1.0/README", tar.TypeReg, 0o644, "hi", ""}), "t.zip", "archive", ""},
		"binary":           {[]byte("ELF"), "tool", "binary", ""},
		"tar symlink":      {tgz(t, entry{"evil", tar.TypeSymlink, 0o777, "", "/etc/passwd"}), "t.tgz", "archive", "not a regular file"},
		"tar hard link":    {tgz(t, entry{"evil", tar.TypeLink, 0o644, "", "x"}), "t.tgz", "archive", "not a regular file"},
		"tar parent":       {tgz(t, entry{"../evil", tar.TypeReg, 0o644, "x", ""}), "t.tgz", "archive", "leaves the archive"},
		"tar inner parent": {tgz(t, entry{"a/../../evil", tar.TypeReg, 0o644, "x", ""}), "t.tgz", "archive", "leaves the archive"},
		"tar absolute":     {tgz(t, entry{"/etc/evil", tar.TypeReg, 0o644, "x", ""}), "t.tgz", "archive", "leaves the archive"},
		"tar duplicate":    {tgz(t, entry{"a", tar.TypeReg, 0o644, "x", ""}, entry{"a", tar.TypeReg, 0o644, "y", ""}), "t.tgz", "archive", "exists"},
		"zip slip":         {zipOf(t, entry{"../../evil", tar.TypeReg, 0o644, "x", ""}), "t.zip", "archive", "leaves the archive"},
		"zip backslash":    {zipOf(t, entry{"..\\evil", tar.TypeReg, 0o644, "x", ""}), "t.zip", "archive", "leaves the archive"},
		"zip symlink":      {zipOf(t, entry{"evil", tar.TypeSymlink, 0o777, "", "/etc/passwd"}), "t.zip", "archive", "not a regular file"},
		"other format":     {[]byte("x"), "t.rar", "archive", "not a .tar.gz"},
		"binary path":      {[]byte("x"), "..", "binary", "not allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			err := Unpack(tc.body, "/r/"+tc.file, tc.kind, dir)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				if _, err := os.Lstat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
					t.Fatal("wrote outside the directory")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == "binary" {
				st, err := os.Stat(filepath.Join(dir, "tool"))
				if err != nil || st.Mode().Perm() != 0o755 {
					t.Fatalf("binary %v %v", st, err)
				}
				return
			}
			st, err := os.Stat(filepath.Join(dir, "tool-1.0", "bin", "tool"))
			if err != nil || st.Mode().Perm() != 0o755 {
				t.Fatalf("executable %v %v", st, err)
			}
			st, err = os.Stat(filepath.Join(dir, "tool-1.0", "README"))
			if err != nil || st.Mode().Perm() != 0o644 {
				t.Fatalf("readme %v %v", st, err)
			}
		})
	}
}

// server serves body at /owner/tool/releases/download/v1/<file> as if it
// were github.com, plus a redirect to another host.
func server(t *testing.T, file string, body []byte) *http.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "https://evil.example/x.tar.gz", http.StatusFound)
		case r.URL.Path == "/hop":
			http.Redirect(w, r, "https://objects.githubusercontent.com/owner/tool/releases/download/v1/"+file, http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/"+file):
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com" // httptest's certificate name
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	c := Client()
	c.Transport = tr
	return c
}

func pin(body []byte, ref string) manifest.Artifact {
	s := sha256.Sum256(body)
	return manifest.Artifact{Platform: "any", Kind: "archive", Ref: ref, SHA256: hex.EncodeToString(s[:]), Size: int64(len(body)), Mount: "/siegekit/files/tool"}
}

func TestFetch(t *testing.T) {
	body := tgz(t, entry{"tool", tar.TypeReg, 0o755, "#!", ""})
	ref := "https://github.com/owner/tool/releases/download/v1/tool.tar.gz"
	c := server(t, "tool.tar.gz", body)
	root := t.TempDir()
	a := pin(body, ref)
	if Installed(root, a) {
		t.Fatal("installed before download")
	}
	if err := Fetch(context.Background(), c, root, a); err != nil {
		t.Fatal(err)
	}
	if !Installed(root, a) {
		t.Fatal("not installed after download")
	}
	if b, err := os.ReadFile(filepath.Join(Dir(root, a), "tool")); err != nil || string(b) != "#!" {
		t.Fatalf("unpacked %q %v", b, err)
	}
	// An allowed redirect is followed.
	hop := a
	hop.Ref = "https://github.com/hop"
	if err := Fetch(context.Background(), c, t.TempDir(), hop); err == nil || !strings.Contains(err.Error(), "unpack ") {
		// /hop has no archive suffix, so it fails only after the download
		// and checks passed.
		t.Errorf("hop: %v", err)
	}

	for name, tc := range map[string]struct {
		edit func(*manifest.Artifact)
		want string
	}{
		"wrong checksum":   {func(a *manifest.Artifact) { a.SHA256 = strings.Repeat("0", 64) }, "does not match the pin"},
		"bigger than pin":  {func(a *manifest.Artifact) { a.Size-- }, "the pin says"},
		"smaller than pin": {func(a *manifest.Artifact) { a.Size++ }, "the pin says"},
		"other host":       {func(a *manifest.Artifact) { a.Ref = "https://example.com/tool.tar.gz" }, "refused"},
		"plain http":       {func(a *manifest.Artifact) { a.Ref = "http://github.com/x/tool.tar.gz" }, "refused"},
		"bad redirect":     {func(a *manifest.Artifact) { a.Ref = "https://github.com/redirect" }, "refused"},
		"not found":        {func(a *manifest.Artifact) { a.Ref = "https://github.com/missing.tar.gz" }, "404"},
	} {
		t.Run(name, func(t *testing.T) {
			b := a
			tc.edit(&b)
			root := t.TempDir()
			err := Fetch(context.Background(), c, root, b)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if Installed(root, b) {
				t.Fatal("installed after a failed check")
			}
			if es, _ := os.ReadDir(root); len(es) != 0 {
				t.Fatalf("left files behind: %v", es)
			}
		})
	}
}
