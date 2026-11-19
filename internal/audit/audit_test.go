package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppend(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	e := Entry{Time: time.Date(2026, 11, 19, 7, 0, 0, 0, time.UTC), Version: "test", Target: "http://localhost:3000/",
		Addresses: []string{"127.0.0.1"}, Mode: "local", Verification: "loopback", Plugins: []string{"zap"}}
	for range 2 {
		if err := Append(p, e); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	n := 0
	for sc := bufio.NewScanner(f); sc.Scan(); n++ {
		var got Entry
		if err := json.Unmarshal(sc.Bytes(), &got); err != nil || got.Target != e.Target || !got.Time.Equal(e.Time) {
			t.Errorf("line %d: %s %v", n, sc.Text(), err)
		}
	}
	if n != 2 {
		t.Errorf("%d lines, want 2", n)
	}
	if err := Append(p, Entry{}); err == nil {
		t.Error("entry without time accepted")
	}
}

func TestAppendRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	link := filepath.Join(dir, "audit.log")
	os.Symlink(victim, link)
	e := Entry{Time: time.Now()}
	if err := Append(link, e); err == nil {
		t.Error("followed a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("victim changed")
	}
	if err := Append(dir, e); err == nil {
		t.Error("wrote to a directory")
	}
}

func TestAppendSizeLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, MaxSize); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Entry{Time: time.Now()}); err == nil {
		t.Error("appended past the size limit")
	}
}
