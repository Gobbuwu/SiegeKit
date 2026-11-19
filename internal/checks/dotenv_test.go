package checks

import (
	"context"
	"path"
	"slices"
	"strings"
	"testing"
)

func TestIsEnvFile(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, ".env.local": true, ".env.production": true, ".env.EXAMPLE": false,
		".env.example": false, ".env.sample": false, ".env.template": false, ".env.dist": false,
		"env": false, ".envrc": false, "x.env": false, ".env.": false,
	} {
		if IsEnvFile(name) != want {
			t.Errorf("IsEnvFile(%q) = %v", name, !want)
		}
	}
}

func TestDotenv(t *testing.T) {
	type result struct{ rule, uri string }
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []result
	}{
		{"not a git repository", map[string]string{".env": "A=1"}, nil},
		{"ignored", map[string]string{".git/HEAD": "", ".gitignore": "node_modules\n.env\n", ".env": "A=1"}, nil},
		{"ignored by glob", map[string]string{".git/HEAD": "", ".gitignore": ".env*\n", ".env.local": "A=1", "app/.env": "B"}, nil},
		{"ignored by info/exclude", map[string]string{".git/HEAD": "", ".git/info/exclude": "/.env\n", ".env": "A=1"}, nil},
		{"anchored pattern does not cover subfolders", map[string]string{".git/HEAD": "", ".gitignore": "/.env\n", "api/.env": "A"},
			[]result{{"env-file-not-ignored", "api/.env"}}},
		{"nested .gitignore", map[string]string{".git/HEAD": "", ".gitignore": "/.env\n", "api/.gitignore": ".env\n", "api/.env": "A", ".env": "B"}, nil},
		{"ignored directory", map[string]string{".git/HEAD": "", ".gitignore": "secrets/\n", "secrets/.env": "A"}, nil},
		{"negated", map[string]string{".git/HEAD": "", ".gitignore": ".env*\n!.env.local\n", ".env.local": "A"},
			[]result{{"env-file-not-ignored", ".env.local"}}},
		{"not ignored", map[string]string{".git/HEAD": "", ".gitignore": "dist\n", ".env": "A", ".env.example": "A="},
			[]result{{"env-file-not-ignored", ".env"}}},
		{"no env file, no rule", map[string]string{".git/HEAD": "", ".gitignore": "dist\n", ".env.example": "A="},
			[]result{{"gitignore-missing-env", ".gitignore"}}},
		{"no .gitignore", map[string]string{".git/HEAD": "", "main.go": ""},
			[]result{{"gitignore-missing-env", ".gitignore"}}},
		{"comment is not a rule", map[string]string{".git/HEAD": "", ".gitignore": "# .env\n"},
			[]result{{"gitignore-missing-env", ".gitignore"}}},
		{"CRLF and **/", map[string]string{".git/HEAD": "", ".gitignore": "**/.env\r\n", "a/b/.env": "A", ".env": "B"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := runDotenv(context.Background(), tree(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			var got []result
			for _, f := range fs {
				got = append(got, result{f.RuleID, f.Location.URI})
				if f.Fingerprint == "" || len(f.Sources) != 1 || f.Sources[0].Plugin != dotenvID {
					t.Errorf("incomplete finding %+v", f)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// FuzzDotenv feeds hostile .gitignore contents and paths to the matcher
// (ADR 0015: every built-in check has a fuzz target in CI).
func FuzzDotenv(f *testing.F) {
	f.Add("*.env\n!.env.example\n/build/\n**/secret\n\\#x\n", "a/b/.env.local")
	f.Add("[\n**\n!\n/\n", ".env")
	f.Fuzz(func(t *testing.T, gitignore, rel string) {
		IsEnvFile(path.Base(rel))
		var rules []ignoreRule
		for _, line := range strings.Split(gitignore, "\n") {
			if r, ok := parseIgnore(line); ok {
				rules = append(rules, r)
			}
		}
		g := &ignores{root: t.TempDir(), cache: map[string][]ignoreRule{}}
		parts := strings.Split(rel, "/")
		if len(parts) > 40 {
			return // the walk stops at 40 levels
		}
		for i := range parts {
			g.cache[strings.Join(parts[:i], "/")] = rules
		}
		g.ignored(rel)
	})
}
