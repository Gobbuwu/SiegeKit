// Package registry reads image manifests from an OCI registry to tell the
// user how much an image download is before they agree to it (ADR 0016). It
// only reads manifests, never layers, and verifies each manifest against its
// digest.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// MaxManifestSize is the largest manifest read.
const MaxManifestSize = 4 << 20

var reRef = regexp.MustCompile(`^([a-z0-9.-]+(?::[0-9]+)?)/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})$`)

const accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// Client reads manifests. The zero value uses http.DefaultClient and the real
// registry hosts.
type Client struct {
	HTTP *http.Client
	// Base maps a registry host to its base URL; for tests.
	Base func(host string) string
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"` // image index
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
}

// DownloadSize returns the compressed size in bytes of image for linux/arch:
// the sum of its layers and config. image must be pinned by digest.
func (c *Client) DownloadSize(ctx context.Context, image, arch string) (int64, error) {
	m := reRef.FindStringSubmatch(image)
	if m == nil {
		return 0, fmt.Errorf("image %q must be pinned by digest", image)
	}
	host, name, digest := m[1], m[2], m[3]
	if host == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	var token string
	for range 2 { // an index, then the platform's manifest
		man, err := c.get(ctx, host, name, digest, &token)
		if err != nil {
			return 0, err
		}
		if len(man.Manifests) == 0 {
			if len(man.Layers) == 0 {
				return 0, errors.New("manifest has no layers")
			}
			n := man.Config.Size
			for _, l := range man.Layers {
				if l.Size < 0 {
					return 0, errors.New("negative layer size")
				}
				n += l.Size
			}
			return n, nil
		}
		digest = ""
		for _, d := range man.Manifests {
			if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == arch {
				digest = d.Digest
				break
			}
		}
		if digest == "" {
			return 0, fmt.Errorf("no linux/%s image", arch)
		}
	}
	return 0, errors.New("nested image index")
}

func (c *Client) get(ctx context.Context, host, name, digest string, token *string) (*manifest, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, fmt.Errorf("unsupported digest %q", digest)
	}
	u := c.base(host) + "/v2/" + name + "/manifests/" + digest
	resp, err := c.do(ctx, u, *token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && *token == "" {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close() // #nosec G104 -- the body is discarded before retrying
		if *token, err = c.fetchToken(ctx, challenge); err != nil {
			return nil, err
		}
		if resp, err = c.do(ctx, u, *token); err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxManifestSize {
		return nil, errors.New("manifest too large")
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("manifest does not match its digest")
	}
	var man manifest
	if err := json.Unmarshal(body, &man); err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return &man, nil
}

func (c *Client) base(host string) string {
	if c.Base != nil {
		return c.Base(host)
	}
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	return "https://" + host
}

func (c *Client) do(ctx context.Context, u, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	return h.Do(req)
}

var reParam = regexp.MustCompile(`([a-z]+)="([^"]*)"`)

// fetchToken gets an anonymous pull token as the registry's Bearer
// challenge describes.
func (c *Client) fetchToken(ctx context.Context, challenge string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", errors.New("registry wants an authentication scheme other than an anonymous token")
	}
	params := map[string]string{}
	for _, m := range reParam.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" && c.Base == nil {
		return "", fmt.Errorf("unusable token address %q", params["realm"])
	}
	q := realm.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	realm.RawQuery = q.Encode()
	resp, err := c.do(ctx, realm.String(), "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token service answered %s", resp.Status)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return "", err
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	if t.Token == "" {
		return "", errors.New("token service returned no token")
	}
	return t.Token, nil
}
