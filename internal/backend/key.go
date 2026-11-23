package backend

// A Supabase public key given by the person (ADR 0061). An app that calls
// Supabase only from its server serves no key in its scripts, so
// backend-live and storage-write take the key from KeyEnv instead. Only
// keys meant to be public are accepted, as from the scripts (ADR 0037).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
)

// KeyEnv is the environment variable that holds a Supabase public key for
// the backend-live and storage-write checks when the app's scripts have
// none. An environment variable, not a flag, so it is not kept in shell
// history or shown in the process list.
const KeyEnv = "SIEGEKIT_SUPABASE_KEY"

// ErrNoKey is the reason a Supabase check has no key.
var ErrNoKey = errors.New("no Supabase public key: the app's scripts have none, and " + KeyEnv + " is not set (an app that calls Supabase only from its server serves no key; set " + KeyEnv + " to the project's anon or publishable key)")

var rePublishableKey = regexp.MustCompile(`^sb_publishable_[A-Za-z0-9_-]{8,}$`)

// ProjectRef is the project ref of a hosted Supabase host
// (REF.supabase.co), or "" for any other host.
func ProjectRef(host string) string {
	ref, rest, ok := strings.Cut(host, ".")
	if !ok || rest != "supabase.co" {
		return ""
	}
	return ref
}

// ParseKey checks the value of KeyEnv before any request. It accepts an
// anon JWT or an sb_publishable_ key, and refuses anything else: secret
// and service-role keys read past row-level security and storage policies,
// so a check run with one would report data any key could not reach. The
// error never holds the key.
func ParseKey(raw string) (string, error) {
	k := strings.TrimSpace(raw)
	switch {
	case k == "":
		return "", fmt.Errorf("%s is empty", KeyEnv)
	case rePublishableKey.MatchString(k):
		return k, nil
	case strings.HasPrefix(k, "sb_secret_"):
		return "", fmt.Errorf("%s holds a secret key (sb_secret_); SiegeKit uses only a public key, the project's anon or publishable key, because a secret key reads past row-level security and storage policies. Nothing was sent", KeyEnv)
	}
	role, _, ok := jwtClaims(k)
	switch {
	case !ok:
		return "", fmt.Errorf("%s is not a Supabase anon key (a JWT) or publishable key (sb_publishable_...). Nothing was sent", KeyEnv)
	case role == "service_role":
		return "", fmt.Errorf("%s holds a service_role key; SiegeKit uses only a public key, the project's anon or publishable key, because a service_role key reads past row-level security and storage policies. Nothing was sent", KeyEnv)
	case role != "anon":
		return "", fmt.Errorf("%s holds a JWT whose role is %q, not anon; SiegeKit uses only the project's anon or publishable key. Nothing was sent", KeyEnv, role)
	}
	return k, nil
}

// KeyForHost reports whether a key accepted by ParseKey can be this host's:
// an anon JWT that names another project is not. A publishable key names
// no project, so only the project itself can tell (KeyAccepted).
func KeyForHost(k, host string) bool {
	return rePublishableKey.MatchString(k) || anonKey(k, ProjectRef(host))
}

// jwtClaims reads a JWT's role and ref claims. Its signature is not
// checked: the backend checks it.
func jwtClaims(k string) (role, ref string, ok bool) {
	parts := strings.Split(k, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", "", false
	}
	var p struct {
		Role string `json:"role"`
		Ref  string `json:"ref"`
	}
	if json.Unmarshal(b, &p) != nil {
		return "", "", false
	}
	return p.Role, p.Ref, true
}

// supabaseHeader carries a public key as supabase-js sends it: in apikey,
// and a JWT also as the bearer token.
func supabaseHeader(key string) http.Header {
	h := http.Header{"Apikey": {key}}
	if strings.HasPrefix(key, "eyJ") {
		h.Set("Authorization", "Bearer "+key)
	}
	return h
}

// SettingsPath is Supabase Auth's public settings, behind the same API key
// check as every other path of a project.
const SettingsPath = "/auth/v1/settings"

// KeyAccepted sends one GET for SettingsPath with key, on a read-only
// configuration, and returns nil only when the project answers with Supabase
// Auth's settings: the project's API gateway accepted the key. Holding a key
// the project accepts, for an app that serves no key, is what ties a
// backend the app's scripts do not name to the person running SiegeKit
// (ADR 0061, owner decision D1). It returns the requests answered (0 or 1).
func KeyAccepted(ctx context.Context, cfg egress.Config, key string) (int, error) {
	if !cfg.ReadOnly {
		return 0, errors.New("the key check runs only on a read-only configuration")
	}
	h := supabaseHeader(key)
	h.Set("Accept", "application/json")
	a, err := send(ctx, cfg, http.MethodGet, SettingsPath, h, nil, MaxAnswer)
	if a == nil {
		return 0, fmt.Errorf("the key in %s could not be checked: %s did not answer: %v", KeyEnv, cfg.Target.Origin(), err)
	}
	if a.Status != http.StatusOK {
		return 1, fmt.Errorf("%s refused the key in %s (GET %s answered %d), so it is not this project's key; nothing else was sent", cfg.Target.Origin(), KeyEnv, SettingsPath, a.Status)
	}
	var s struct {
		External map[string]json.RawMessage `json:"external"`
	}
	if err != nil || json.Unmarshal(a.Body, &s) != nil || s.External == nil {
		return 1, fmt.Errorf("GET %s on %s did not answer with Supabase Auth's settings, so SiegeKit cannot tell the project accepted the key in %s; nothing else was sent", SettingsPath, cfg.Target.Origin(), KeyEnv)
	}
	return 1, nil
}
