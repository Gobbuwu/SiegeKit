package wordlists

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"slices"
	"testing"
)

// TestPinned checks the shipped SecLists file is the pinned one, byte for
// byte: tag 2026.2, 4,751 paths.
func TestPinned(t *testing.T) {
	b, err := Get("seclists-common.txt")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a" || len(b) != 38536 {
		t.Errorf("seclists-common.txt: sha256 %s, %d bytes", got, len(b))
	}
}

// TestLists checks every shipped list is listed in Names and holds one
// relative path per line (SecLists has a few with spaces), and SiegeKit's
// own list no duplicates.
func TestLists(t *testing.T) {
	names, err := fs.Glob(lists, "*.txt")
	if err != nil || !slices.Equal(names, Names) {
		t.Fatalf("embedded %v, Names %v (%v)", names, Names, err)
	}
	for _, n := range Names {
		b, _ := Get(n)
		lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
		seen := map[string]bool{}
		for i, l := range lines {
			if len(l) == 0 || l[0] == '/' || bytes.ContainsAny(l, "\t\r") {
				t.Errorf("%s line %d: %q", n, i+1, l)
			}
			if n == "deployed.txt" && seen[string(l)] {
				t.Errorf("%s line %d: duplicate %q", n, i+1, l)
			}
			seen[string(l)] = true
		}
		if n == "deployed.txt" && (len(lines) < 150 || len(lines) > 250) {
			t.Errorf("%s has %d paths, want about 200", n, len(lines))
		}
	}
	if _, err := Get("other.txt"); err == nil {
		t.Error("unknown list accepted")
	}
}
