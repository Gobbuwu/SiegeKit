// Package store keeps run results on the local disk so runs can be compared
// (ADR 0013). Nothing is sent anywhere.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

// Store saves runs as one JSON file each under Dir, readable only by the user.
type Store struct {
	Dir string
}

// A run ID is the start time, the target slug (at most 40 characters) and,
// for a second run of the same target in the same second, "-2" to "-9".
var reRunID = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-z0-9-]{1,42}$`)

// Save writes the run and returns its ID. The file is written to a temporary
// name and renamed, so a crash never leaves a half-written run.
func (s *Store) Save(r *report.Run, targetSlug string) (string, error) {
	slug := slugify(targetSlug)
	id := r.Started.UTC().Format("20060102T150405Z") + "-" + slug
	if !reRunID.MatchString(id) {
		return "", fmt.Errorf("invalid run id %q", id)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(s.Dir, ".run-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close() // #nosec G104 -- the chmod error is returned instead
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() // #nosec G104 -- the write error is returned instead
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	// Existing runs are never overwritten (ADR 0013). A second run of the
	// same target in the same second gets a suffix.
	base := id
	for n := 2; ; n++ {
		// Claim the name with O_EXCL, so two runs finishing at once never
		// take the same file, then move the finished run over the claim.
		final := filepath.Join(s.Dir, id+".json")
		claim, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- id is checked against reRunID
		if err == nil {
			claim.Close() // #nosec G104 -- empty file; the rename below replaces it
			if err := os.Rename(tmp.Name(), final); err != nil {
				os.Remove(final) // #nosec G104 -- best effort; the rename error is returned
				return "", err
			}
			return id, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if n > 9 {
			return "", fmt.Errorf("run %s already exists", id)
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
}

// Load reads a saved run by ID.
func (s *Store) Load(id string) (*report.Run, error) {
	if !reRunID.MatchString(id) {
		return nil, fmt.Errorf("invalid run id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, id+".json")) // #nosec G304 -- id is checked against reRunID above
	if err != nil {
		return nil, err
	}
	var r report.Run
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode run %s: %w", id, err)
	}
	return &r, nil
}

// List returns saved run IDs, oldest first. IDs sort by time because they
// start with a UTC timestamp.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && e.Type().IsRegular() && reRunID.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Latest returns the most recent saved run of target, or "" and nil if
// there is none. Runs that cannot be read are passed over.
func (s *Store) Latest(target string) (string, *report.Run, error) {
	ids, err := s.List()
	if err != nil {
		return "", nil, err
	}
	for i := len(ids) - 1; i >= 0; i-- {
		r, err := s.Load(ids[i])
		if err == nil && r.Target == target {
			return ids[i], r, nil
		}
	}
	return "", nil, nil
}

// Comparison compares cur with the saved run prev, whose ID is id.
// Findings that prev itself could not check again are still open, so they
// stay in the baseline: a later run reports them as fixed or still present,
// never as new.
func Comparison(id string, prev, cur *report.Run) *report.Comparison {
	base := *prev
	if prev.Comparison != nil && len(prev.Comparison.NotRechecked) > 0 {
		base.Findings = append(append([]findings.Finding(nil), prev.Findings...), prev.Comparison.NotRechecked...)
	}
	d := Compare(&base, cur)
	c := &report.Comparison{
		PreviousRun: id, PreviousStarted: prev.Started, PreviousVersion: prev.SiegeKitVersion,
		New: []string{}, Fixed: d.Fixed, NotRechecked: []findings.Finding{},
	}
	if c.Fixed == nil {
		c.Fixed = []findings.Finding{}
	}
	for _, f := range d.New {
		c.New = append(c.New, f.Fingerprint)
	}
	inCur := map[string]bool{}
	for _, f := range cur.Findings {
		inCur[f.Fingerprint] = true
	}
	for _, f := range d.Still {
		if inCur[f.Fingerprint] {
			c.StillPresent++
		} else {
			c.NotRechecked = append(c.NotRechecked, f)
		}
	}
	return c
}

// Diff compares two runs by finding fingerprint.
type Diff struct {
	New   []findings.Finding `json:"new"`
	Fixed []findings.Finding `json:"fixed"`
	Still []findings.Finding `json:"still"`
}

// Compare returns what is new in cur, what disappeared since prev, and what
// remains. A finding that disappeared is only "fixed" if the plugin that
// reported it ran to completion in cur; otherwise it is still listed.
func Compare(prev, cur *report.Run) Diff {
	ranInCur := map[string]bool{}
	for _, p := range cur.Plugins {
		if p.Status == report.Ran {
			ranInCur[p.ID] = true
		}
	}
	inCur := map[string]bool{}
	for _, f := range cur.Findings {
		inCur[f.Fingerprint] = true
	}
	inPrev := map[string]bool{}
	var d Diff
	for _, f := range prev.Findings {
		inPrev[f.Fingerprint] = true
		if inCur[f.Fingerprint] {
			continue
		}
		recheck := false
		for _, s := range f.Sources {
			if ranInCur[s.Plugin] {
				recheck = true
			}
		}
		if recheck {
			d.Fixed = append(d.Fixed, f)
		} else {
			d.Still = append(d.Still, f)
		}
	}
	for _, f := range cur.Findings {
		if inPrev[f.Fingerprint] {
			d.Still = append(d.Still, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	findings.Sort(d.New)
	findings.Sort(d.Fixed)
	findings.Sort(d.Still)
	return d
}

var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.Trim(reSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	if s == "" {
		s = "target"
	}
	return s
}
