package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func digest(b string) string {
	s := sha256.Sum256([]byte(b))
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestDownloadSize(t *testing.T) {
	img := `{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"size":100},"layers":[{"size":1000},{"size":2000}]}`
	index := `{"manifests":[{"digest":"sha256:` + strings.Repeat("0", 64) + `","platform":{"os":"linux","architecture":"arm64"}},{"digest":"` + digest(img) + `","platform":{"os":"linux","architecture":"amd64"}}]}`
	tampered := strings.Replace(img, "1000", "1", 1)
	blobs := map[string]string{digest(index): index, digest(img): img, digest(img + " "): tampered}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.URL.Query().Get("scope") != "repository:library/tool:pull" {
				http.Error(w, "bad scope", http.StatusBadRequest)
				return
			}
			w.Write([]byte(`{"token":"t0k"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test",scope="repository:library/tool:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		d := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if !strings.HasPrefix(r.URL.Path, "/v2/library/tool/manifests/") || blobs[d] == "" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(blobs[d]))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Base: func(string) string { return srv.URL }}
	ctx := context.Background()

	n, err := c.DownloadSize(ctx, "docker.io/tool@"+digest(index), "amd64")
	if err != nil || n != 3100 {
		t.Fatalf("index: %d %v", n, err)
	}
	if n, err = c.DownloadSize(ctx, "docker.io/tool@"+digest(img), "amd64"); err != nil || n != 3100 {
		t.Fatalf("single manifest: %d %v", n, err)
	}
	for name, tc := range map[string]struct{ ref, arch, want string }{
		"not pinned":   {"docker.io/tool:latest", "amd64", "pinned by digest"},
		"no platform":  {"docker.io/tool@" + digest(index), "s390x", "no linux/s390x"},
		"tampered":     {"docker.io/tool@" + digest(img+" "), "amd64", "does not match its digest"},
		"not found":    {"docker.io/tool@" + digest("x"), "amd64", "404"},
		"missing arch": {"docker.io/tool@" + digest(index), "arm64", "404"},
	} {
		if _, err := c.DownloadSize(ctx, tc.ref, tc.arch); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func TestFetchTokenRejectsOtherSchemes(t *testing.T) {
	if _, err := (&Client{}).fetchToken(context.Background(), `Basic realm="x"`); err == nil {
		t.Error("Basic challenge accepted")
	}
	if _, err := (&Client{}).fetchToken(context.Background(), `Bearer realm="http://example.invalid/token"`); err == nil {
		t.Error("plain-HTTP token address accepted")
	}
}

func TestGetRefusals(t *testing.T) {
	bad := `{not json`
	big := strings.Repeat(" ", MaxManifestSize+1)
	blobs := map[string]string{digest(bad): bad, digest(big): big}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if d == digest("teapot") {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.Write([]byte(blobs[d]))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Base: func(string) string { return srv.URL }}
	tok := "t"
	for name, tc := range map[string]struct{ digest, want string }{
		"sha512":    {"sha512:" + strings.Repeat("0", 128), "unsupported digest"},
		"not json":  {digest(bad), "read manifest"},
		"too large": {digest(big), "manifest too large"},
		"status":    {digest("teapot"), "418"},
	} {
		if _, err := c.get(context.Background(), "docker.io", "library/tool", tc.digest, &tok); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	// Without a server, the request itself fails.
	srv.Close()
	if _, err := c.get(context.Background(), "docker.io", "library/tool", digest(bad), &tok); err == nil {
		t.Error("closed server: no error")
	}
}

func TestBase(t *testing.T) {
	c := &Client{}
	if got := c.base("docker.io"); got != "https://registry-1.docker.io" {
		t.Errorf("docker.io: %s", got)
	}
	if got := c.base("ghcr.io"); got != "https://ghcr.io" {
		t.Errorf("ghcr.io: %s", got)
	}
}
