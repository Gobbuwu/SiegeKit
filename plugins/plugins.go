// Package plugins embeds SiegeKit's built-in plugin manifests, one directory
// per plugin, so the binary carries the exact pinned versions it was tested with.
package plugins

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
)

//go:embed */plugin.json
var files embed.FS

// Builtin parses and returns every built-in plugin, sorted by ID. Each
// manifest's ID must equal its directory name.
func Builtin() ([]*manifest.Manifest, error) {
	names, err := fs.Glob(files, "*/plugin.json")
	if err != nil {
		return nil, err
	}
	var out []*manifest.Manifest
	for _, name := range names {
		data, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		m, err := manifest.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if dir := path.Dir(name); m.ID != dir {
			return nil, fmt.Errorf("%s: id %q does not match directory %q", name, m.ID, dir)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
