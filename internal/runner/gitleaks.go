package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// gitleaksRepoConfig is the repository's own Gitleaks settings file, which
// Gitleaks reads by itself only when no other configuration is given.
const gitleaksRepoConfig = ".gitleaks.toml"

// maxGitleaksRepoConfig caps the repository's .gitleaks.toml that SiegeKit
// reads. Real files are a few KiB; a larger one fails the check, saying so.
const maxGitleaksRepoConfig = 1 << 20

// gitleaksDefaults makes Gitleaks use its default rules, which is what it
// does by itself in a repository without a .gitleaks.toml.
const gitleaksDefaults = "[extend]\nuseDefault = true\n"

// gitleaksConfig builds the configuration for a plugin with
// run.gitleaksRules (ADR 0063): the repository's .gitleaks.toml, as Gitleaks
// would read it by itself, or Gitleaks' default rules when there is none,
// followed by SiegeKit's rules. It writes the file into work and returns the
// run's environment, the file and a line for the report saying which rules
// applied.
//
// The repository's file is appended to rather than extended with [extend]
// path: Gitleaks follows at most two [extend] levels, so a repository file
// that extends another file which uses the defaults would silently lose the
// default rules (measured with gitleaks 8.30.1, 2026-11-23).
func gitleaksConfig(m *manifest.Manifest, target, work string) (env map[string]string, file, input string, err error) {
	ids := m.Run.GitleaksRuleIDs()
	base, from := gitleaksDefaults, "Gitleaks' default rules"
	repo, err := readRepoConfig(filepath.Join(target, gitleaksRepoConfig))
	if err != nil {
		return nil, "", "", err
	}
	if repo != nil {
		for _, id := range ids {
			// A repository rule with the same id would be replaced by
			// SiegeKit's without a word; refuse instead.
			if regexp.MustCompile(`\bid["']?\s*=\s*["']{1,3}` + regexp.QuoteMeta(id) + `["']`).Match(repo) {
				return nil, "", "", fmt.Errorf("the repository's %s defines a rule with the id %q, which SiegeKit adds too; rename the repository's rule so both apply", gitleaksRepoConfig, id)
			}
		}
		base, from = string(repo), "the rules in the repository's "+gitleaksRepoConfig
	}
	file = filepath.Join(work, m.ID+"-config.toml")
	cfg := base + "\n\n" + m.Run.GitleaksRules
	// #nosec G306 -- the tool runs as another user and must read the file; it holds rules, not secrets
	if err := os.WriteFile(file, []byte(cfg), 0o644); err != nil {
		return nil, "", "", fmt.Errorf("write the Gitleaks configuration: %w", err)
	}
	env = maps.Clone(m.Run.Env)
	if env == nil {
		env = map[string]string{}
	}
	env["GITLEAKS_CONFIG"] = sandbox.ConfigMountTOML
	return env, file, from + " and SiegeKit's rules " + strings.Join(ids, ", "), nil
}

// readRepoConfig reads the repository's .gitleaks.toml without following a
// link. It returns nil when there is none. A file SiegeKit cannot use as it
// is (a link, a folder, too large, not UTF-8 text) is an error, so the check
// never runs without rules the repository asked for.
func readRepoConfig(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- a fixed name at the target's top level; links refused, size limited
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("the repository's %s is a link; SiegeKit does not follow it, so it cannot apply the repository's rules", gitleaksRepoConfig)
	case err != nil:
		return nil, fmt.Errorf("read the repository's %s: %w", gitleaksRepoConfig, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read the repository's %s: %w", gitleaksRepoConfig, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("the repository's %s is not a regular file, so SiegeKit cannot apply the repository's rules", gitleaksRepoConfig)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxGitleaksRepoConfig+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("read the repository's %s: %w", gitleaksRepoConfig, err)
	case len(b) > maxGitleaksRepoConfig:
		return nil, fmt.Errorf("the repository's %s is larger than %d bytes, so SiegeKit does not read it", gitleaksRepoConfig, maxGitleaksRepoConfig)
	case !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0:
		return nil, fmt.Errorf("the repository's %s is not UTF-8 text", gitleaksRepoConfig)
	}
	return b, nil
}
