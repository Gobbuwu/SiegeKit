// Package trivy converts Trivy's JSON report to findings (ADR 0063).
//
// Trivy's SARIF output cannot say whether a vulnerable package is a
// development dependency, so SiegeKit reads the JSON report written with
// --list-all-pkgs, whose package list carries a "Dev" flag. The findings
// keep what the SARIF output gave (rule ID, title, message, severity,
// location), so fingerprints do not change, and add the dev-dependency note
// and the CWE IDs the JSON report has. The report is untrusted input (threat
// model T7): size is limited and values are only decoded.
package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

// DevNote ends the message of a finding in a development dependency.
const DevNote = " This is a development dependency: it is not part of the built app, but it runs on developer machines and in builds and CI, so a flaw in it can still reach your code and secrets."

type report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  *string  `json:"ArtifactName"`
	Results       []result `json:"Results"`
}

type result struct {
	Target          string `json:"Target"`
	Packages        []pkg  `json:"Packages"`
	Vulnerabilities []vuln `json:"Vulnerabilities"`
}

type pkg struct {
	Name       string     `json:"Name"`
	Version    string     `json:"Version"`
	Dev        bool       `json:"Dev"`
	Identifier identifier `json:"Identifier"`
	Locations  []struct {
		StartLine int `json:"StartLine"`
	} `json:"Locations"`
}

type identifier struct {
	UID string `json:"UID"`
}

type vuln struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgName          string     `json:"PkgName"`
	PkgPath          string     `json:"PkgPath"`
	PkgIdentifier    identifier `json:"PkgIdentifier"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	Title            string     `json:"Title"`
	Severity         string     `json:"Severity"`
	SeveritySource   string     `json:"SeveritySource"`
	PrimaryURL       string     `json:"PrimaryURL"`
	CweIDs           []string   `json:"CweIDs"`
	CVSS             map[string]struct {
		V3Score float64 `json:"V3Score"`
	} `json:"CVSS"`
}

// Options control conversion.
type Options struct {
	Plugin    string // plugin id recorded as the source
	Family    string // test family
	MountPath string // container path of the target, removed from file names
}

var reCWE = regexp.MustCompile(`^CWE-[1-9][0-9]{0,4}$`)

// ToFindings reads a Trivy JSON report (schema version 2) and converts every
// vulnerability.
func ToFindings(r io.Reader, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("trivy report larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("decode Trivy report: %w", err)
	}
	// Results is left out when nothing was found, so the schema version and
	// artifact name are what show that this is a Trivy report at all.
	if rep.SchemaVersion != 2 || rep.ArtifactName == nil {
		return nil, fmt.Errorf("decode Trivy report: schema version %d, want 2 with an artifact name", rep.SchemaVersion)
	}
	var out []findings.Finding
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" {
				return nil, errors.New("decode Trivy report: vulnerability without an ID")
			}
			path := res.Target
			if v.PkgPath != "" {
				path = v.PkgPath
			}
			loc, dev := place(v, res.Packages)
			f := findings.Finding{
				RuleID:   v.VulnerabilityID,
				Title:    v.Title,
				Message:  message(v),
				Severity: severity(v),
				CWEs:     cwes(v.CweIDs),
				Location: findings.Location{URI: sarif.RelURI(path, opt.MountPath), StartLine: loc},
				HelpURI:  findings.SafeHelpURI(v.PrimaryURL),
				Family:   opt.Family,
				Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: v.VulnerabilityID}},
			}
			if f.Title == "" {
				f.Title = v.VulnerabilityID
			}
			if dev {
				f.Message += DevNote
			}
			f.ComputeFingerprint()
			out = append(out, f)
		}
	}
	return out, nil
}

// message is the text Trivy's SARIF output gives a vulnerability (Trivy
// 0.76.2, pkg/report/sarif.go).
func message(v vuln) string {
	return fmt.Sprintf("Package: %v\nInstalled Version: %v\nVulnerability %v\nSeverity: %v\nFixed Version: %v\nLink: [%v](%v)",
		v.PkgName, v.InstalledVersion, v.VulnerabilityID, v.Severity, v.FixedVersion, v.VulnerabilityID, v.PrimaryURL)
}

// place returns the line Trivy's SARIF output gives the vulnerability (the
// first location of the first package with the same name and version, or
// line 1) and whether the vulnerable package is a development dependency.
// The package is found by its unique ID when the report has one, so a dev
// and a production copy of the same version are told apart.
func place(v vuln, pkgs []pkg) (line int, dev bool) {
	line = 1
	found := false
	for _, p := range pkgs {
		if p.Name != v.PkgName || p.Version != v.InstalledVersion {
			continue
		}
		if !found {
			found = true
			if len(p.Locations) > 0 && p.Locations[0].StartLine > 0 {
				line = p.Locations[0].StartLine
			}
			if v.PkgIdentifier.UID == "" {
				return line, p.Dev
			}
		}
		if v.PkgIdentifier.UID != "" && p.Identifier.UID == v.PkgIdentifier.UID {
			dev = p.Dev
		}
	}
	return line, dev
}

// severity follows Trivy's SARIF score: the CVSS v3 score of the severity
// source when there is one, otherwise Trivy's severity, read with SiegeKit's
// SARIF thresholds (9.0 critical, 7.0 high, 4.0 medium, above 0 low).
func severity(v vuln) findings.Severity {
	score := map[string]float64{"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}[v.Severity]
	if c, ok := v.CVSS[v.SeveritySource]; ok && c.V3Score != 0 {
		score = c.V3Score
	}
	switch {
	case score >= 9:
		return findings.Critical
	case score >= 7:
		return findings.High
	case score >= 4:
		return findings.Medium
	case score > 0:
		return findings.Low
	}
	return findings.Info
}

func cwes(ids []string) []string {
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if reCWE.MatchString(id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
