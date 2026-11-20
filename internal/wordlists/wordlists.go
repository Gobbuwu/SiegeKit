// Package wordlists holds the path lists that SiegeKit ships for tools that
// guess paths, such as ffuf (ADR 0027). They are part of the binary, so a
// scan downloads nothing for them.
package wordlists

import (
	"embed"
	"fmt"
	"slices"
)

//go:embed *.txt
var lists embed.FS

// Names are the lists shipped:
//   - seclists-common.txt: SecLists Discovery/Web-Content/common.txt, tag
//     2026.2 (commit 145f1f45ba7bc5fd6b3966d3a79bf95654deb20e), MIT; see
//     THIRD_PARTY.md. Local targets.
//   - deployed.txt: SiegeKit's own short list (about 200 paths: backups,
//     version control, environment files, admin panels). Deployed targets.
var Names = []string{"deployed.txt", "seclists-common.txt"}

// Get returns the named list.
func Get(name string) ([]byte, error) {
	if !slices.Contains(Names, name) {
		return nil, fmt.Errorf("unknown wordlist %q", name)
	}
	return lists.ReadFile(name)
}
