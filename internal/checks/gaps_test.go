package checks

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/report"
)

// Files and folders SiegeKit's own checks do not read are named (ADR 0067):
// a text file over MaxFileSize, a folder deeper than MaxDepth. A large
// binary file is not, and neither are dependency folders, which the "Not
// tested by SiegeKit" list names.
func TestWalkNamesGaps(t *testing.T) {
	big := strings.Repeat("password = 'hunter2'\n", MaxFileSize/20+10)
	deep := strings.Repeat("d/", MaxDepth+1) + "x.txt"
	root := tree(t, map[string]string{
		"big.sql":                   big,
		"image.bin":                 "\x00" + big,
		"small.txt":                 "ok",
		"node_modules/big.js":       big,
		deep:                        "deep",
		"firebase/storage.rules":    "rules_version = '2';",
		"supabase/migrations/a.sql": big,
	})
	o, err := weakPasswords.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range o.Gaps {
		got = append(got, string(g.Cause)+" "+g.Path)
	}
	slices.Sort(got)
	want := []string{"too-deep " + strings.Repeat("d/", MaxDepth+1), "too-large big.sql", "too-large supabase/migrations/a.sql"}
	if !slices.Equal(got, want) {
		t.Fatalf("gaps %q, want %q", got, want)
	}
	s, err := ReadSource(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Gaps) != 2 || s.Gaps[0].Cause != report.GapTooDeep && s.Gaps[1].Cause != report.GapTooDeep {
		t.Fatalf("source gaps %+v", s.Gaps)
	}
}

func TestDotenvNamesLargeIgnoreFile(t *testing.T) {
	var g gaps
	root := tree(t, map[string]string{".git/HEAD": "", ".gitignore": strings.Repeat("#\n", MaxFileSize), ".env": "A=1"})
	if _, err := runDotenv(context.Background(), root, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.list) != 1 || g.list[0].Path != ".gitignore" || g.list[0].Cause != report.GapTooLarge {
		t.Fatalf("gaps %+v", g.list)
	}
}
