package checks

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// dotenv warns when environment files (.env) are not excluded from git, so
// the next "git add ." would commit them. Files already committed are found
// by the gitleaks-history plugin. It only runs on git repositories.
const dotenvID = "dotenv-gitignore"

var dotenv = Check{
	ID:      dotenvID,
	Name:    "Environment files left out of git",
	Family:  "secrets",
	Targets: []string{"repo"},
	Run:     noResult(runDotenv),
}

// envTemplates are committed on purpose and hold no real values.
var envTemplates = map[string]bool{"example": true, "sample": true, "template": true, "dist": true}

// IsEnvFile reports whether base is an environment file (.env or .env.*)
// that is not a template such as .env.example.
func IsEnvFile(base string) bool {
	if base == ".env" {
		return true
	}
	rest, ok := strings.CutPrefix(base, ".env.")
	return ok && rest != "" && !envTemplates[strings.ToLower(rest)]
}

func runDotenv(ctx context.Context, root string) ([]findings.Finding, error) {
	if st, err := os.Lstat(filepath.Join(root, ".git")); err != nil || !st.IsDir() {
		return nil, nil
	}
	var envFiles []string
	err := walkTree(ctx, root, func(_, rel string) error {
		if IsEnvFile(path.Base(rel)) {
			envFiles = append(envFiles, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ig := &ignores{root: root, cache: map[string][]ignoreRule{}}
	var out []findings.Finding
	for _, rel := range envFiles {
		if ig.ignored(rel) {
			continue
		}
		out = append(out, findings.Finding{
			RuleID:   "env-file-not-ignored",
			Title:    "Environment file is not excluded by .gitignore",
			Message:  rel + " is not listed in .gitignore, so \"git add .\" would commit it and any secrets in it. Add .env (or .env*) to .gitignore and keep only a template such as .env.example in git.",
			Severity: findings.Medium,
			CWEs:     []string{"CWE-538"},
			Location: findings.Location{URI: rel},
			Family:   "secrets",
		})
	}
	if len(envFiles) == 0 && !ig.ignored(".env") {
		out = append(out, findings.Finding{
			RuleID:   "gitignore-missing-env",
			Title:    ".gitignore does not exclude .env",
			Message:  "The repository's .gitignore does not exclude .env. If you or a tool create one, \"git add .\" would commit it. Add .env (or .env*) to .gitignore.",
			Severity: findings.Low,
			CWEs:     []string{"CWE-538"},
			Location: findings.Location{URI: ".gitignore"},
			Family:   "secrets",
		})
	}
	for i := range out {
		out[i].Sources = []findings.Source{{Plugin: dotenvID, RuleID: out[i].RuleID}}
		out[i].ComputeFingerprint()
	}
	return out, nil
}

// ignoreRule is one .gitignore line.
type ignoreRule struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
}

// ignores answers whether a path is ignored by the .gitignore files on its
// way from the root, plus .git/info/exclude. It follows git's rules for the
// common cases: comments, negation, directory-only patterns, anchoring by a
// slash, and a leading "**/". Other uses of "**" are matched as "*".
type ignores struct {
	root  string
	cache map[string][]ignoreRule // by directory, "" for the root
}

func (g *ignores) rules(dir string) []ignoreRule {
	if r, ok := g.cache[dir]; ok {
		return r
	}
	var rules []ignoreRule
	files := []string{filepath.Join(g.root, filepath.FromSlash(dir), ".gitignore")}
	if dir == "" {
		files = append([]string{filepath.Join(g.root, ".git", "info", "exclude")}, files...)
	}
	for _, f := range files {
		data, err := readFile(f)
		if err != nil || data == nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if r, ok := parseIgnore(line); ok {
				rules = append(rules, r)
			}
		}
	}
	g.cache[dir] = rules
	return rules
}

func parseIgnore(line string) (ignoreRule, bool) {
	line = strings.TrimRight(line, "\r")
	line = strings.TrimRight(line, " \t")
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var r ignoreRule
	if strings.HasPrefix(line, "!") {
		r.negate, line = true, line[1:]
	}
	line = strings.TrimPrefix(line, "\\")
	if strings.HasSuffix(line, "/") {
		r.dirOnly, line = true, strings.TrimRight(line, "/")
	}
	if p, ok := strings.CutPrefix(line, "**/"); ok {
		line = p
	} else if strings.Contains(line, "/") {
		r.anchored, line = true, strings.TrimPrefix(line, "/")
	}
	line = strings.ReplaceAll(line, "**", "*")
	if line == "" {
		return ignoreRule{}, false
	}
	r.pattern = line
	return r, true
}

// ignored reports whether the file at rel (slash-separated) is ignored. As
// in git, a file inside an ignored directory is ignored, and the last
// matching rule wins, with deeper .gitignore files after shallower ones.
func (g *ignores) ignored(rel string) bool {
	parts := strings.Split(rel, "/")
	// A parent directory that is ignored hides everything in it.
	for i := 1; i < len(parts); i++ {
		if g.match(strings.Join(parts[:i], "/"), true) {
			return true
		}
	}
	return g.match(rel, false)
}

// match applies the rules of every directory above p to p itself.
func (g *ignores) match(p string, isDir bool) bool {
	parts := strings.Split(p, "/")
	result := false
	for depth := 0; depth < len(parts); depth++ {
		dir := strings.Join(parts[:depth], "/")
		sub := strings.Join(parts[depth:], "/")
		for _, r := range g.rules(dir) {
			if r.dirOnly && !isDir {
				continue
			}
			target := sub
			if !r.anchored {
				target = path.Base(sub)
			}
			if ok, _ := path.Match(r.pattern, target); ok {
				result = !r.negate
			}
		}
	}
	return result
}
