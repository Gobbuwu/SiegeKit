package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

func TestFileMounts(t *testing.T) {
	list := manifest.Artifact{Platform: "any", Kind: "archive", Ref: "https://github.com/o/r/releases/download/v1/list.zip", SHA256: strings.Repeat("1", 64), Size: 10, Mount: "/siegekit/files/list"}
	bin := manifest.Artifact{Platform: "linux/" + runtime.GOARCH, Kind: "binary", Ref: "https://github.com/o/r/releases/download/v1/tool", SHA256: strings.Repeat("2", 64), Size: 10, Mount: "/siegekit/files/tool"}
	mac := manifest.Artifact{Platform: "darwin/" + runtime.GOARCH, Kind: "binary", Ref: "https://github.com/o/r/releases/download/v1/tool-mac", SHA256: strings.Repeat("3", 64), Size: 10, Mount: "/siegekit/files/tool"}
	img := manifest.Artifact{Platform: "any", Kind: "oci-image", Ref: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64), SHA256: strings.Repeat("a", 64)}
	m := &manifest.Manifest{ID: "p", Tool: &manifest.Tool{Artifacts: []manifest.Artifact{img, list, bin, mac}}}

	if fs := FilesFor(m); len(fs) != 2 || fs[0].SHA256 != list.SHA256 || fs[1].SHA256 != bin.SHA256 {
		t.Fatalf("files for linux: %+v", fs)
	}
	root := t.TempDir()
	if _, err := FileMounts(m, root); err == nil || !strings.Contains(err.Error(), "pinned file list.zip is not installed") {
		t.Errorf("missing file: %v", err)
	}
	for _, a := range []manifest.Artifact{list, bin} {
		if err := os.Mkdir(filepath.Join(root, a.SHA256), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, a.SHA256+".ok"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := FileMounts(m, root)
	want := []sandbox.FileMount{{Host: filepath.Join(root, list.SHA256), Mount: list.Mount}, {Host: filepath.Join(root, bin.SHA256), Mount: bin.Mount}}
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("mounts %+v %v", got, err)
	}
	if _, err := FileMounts(m, ""); err == nil {
		t.Error("no files directory accepted")
	}
	// A plugin without files needs no directory.
	if got, err := FileMounts(&manifest.Manifest{Tool: &manifest.Tool{Artifacts: []manifest.Artifact{img}}}, ""); err != nil || got != nil {
		t.Errorf("no files: %+v %v", got, err)
	}
}
