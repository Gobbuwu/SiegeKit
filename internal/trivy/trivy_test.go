package trivy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// sample is shaped like Trivy 0.76.2's JSON with --list-all-pkgs and
// --include-dev-deps (fields checked against the recording in
// internal/runner/testdata/recorded/trivy.json): one production and one
// development dependency, and the same package and version twice, once in
// production and once in development, told apart by their UIDs.
const sample = `{
  "SchemaVersion": 2,
  "ArtifactName": "/target",
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Packages": [
        {"Name": "lodash", "Version": "4.17.20", "Identifier": {"UID": "p1"}, "Locations": [{"StartLine": 5, "EndLine": 5}]},
        {"Name": "minimist", "Version": "1.2.5", "Dev": true, "Identifier": {"UID": "d1"}, "Locations": [{"StartLine": 6, "EndLine": 6}]},
        {"Name": "qs", "Version": "6.0.0", "Identifier": {"UID": "p2"}, "Locations": [{"StartLine": 9, "EndLine": 9}, {"StartLine": 20, "EndLine": 20}]},
        {"Name": "qs", "Version": "6.0.0", "Dev": true, "Identifier": {"UID": "d2"}, "Locations": [{"StartLine": 30, "EndLine": 30}]}
      ],
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "PkgIdentifier": {"UID": "p1"}, "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
         "Title": "lodash: command injection", "Severity": "HIGH", "SeveritySource": "ghsa", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
         "CweIDs": ["CWE-94", "CWE-94", "not a cwe"], "CVSS": {"ghsa": {"V3Score": 7.2}, "nvd": {"V3Score": 9.9}}},
        {"VulnerabilityID": "CVE-2021-44906", "PkgName": "minimist", "PkgIdentifier": {"UID": "d1"}, "InstalledVersion": "1.2.5", "FixedVersion": "1.2.6",
         "Title": "minimist: prototype pollution", "Severity": "CRITICAL", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-44906", "CweIDs": ["CWE-1321"]},
        {"VulnerabilityID": "CVE-2022-24999", "PkgName": "qs", "PkgIdentifier": {"UID": "p2"}, "InstalledVersion": "6.0.0", "Severity": "MEDIUM"},
        {"VulnerabilityID": "CVE-2022-24999", "PkgName": "qs", "PkgIdentifier": {"UID": "d2"}, "InstalledVersion": "6.0.0", "Severity": "MEDIUM"}
      ]
    },
    {
      "Target": "requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Packages": [{"Name": "django", "Version": "2.2.0"}],
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2019-14234", "PkgName": "django", "InstalledVersion": "2.2.0", "Severity": "LOW", "PrimaryURL": "http://insecure.example/x"},
        {"VulnerabilityID": "CVE-2000-0001", "PkgName": "django", "PkgPath": "/target/vendor/django/METADATA", "InstalledVersion": "2.2.0", "Severity": "UNKNOWN"}
      ]
    }
  ]
}`

func TestToFindings(t *testing.T) {
	fs, err := ToFindings(strings.NewReader(sample), Options{Plugin: "trivy", Family: "sca", MountPath: "/target"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 6 {
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	type want struct {
		title, uri string
		line       int
		sev        findings.Severity
		dev        bool
		cwes       string
		help       string
	}
	for i, w := range []want{
		// The severity source's CVSS v3 score (7.2) wins over the label and
		// over other sources, as in Trivy's SARIF output.
		{"lodash: command injection", "package-lock.json", 5, findings.High, false, "CWE-94", "https://avd.aquasec.com/nvd/cve-2021-23337"},
		{"minimist: prototype pollution", "package-lock.json", 6, findings.Critical, true, "CWE-1321", "https://avd.aquasec.com/nvd/cve-2021-44906"},
		// The first location of the first package with that name and
		// version, as in Trivy's SARIF output; dev only for the dev copy.
		{"CVE-2022-24999", "package-lock.json", 9, findings.Medium, false, "", ""},
		{"CVE-2022-24999", "package-lock.json", 9, findings.Medium, true, "", ""},
		// No location: line 1. Only https help links are kept.
		{"CVE-2019-14234", "requirements.txt", 1, findings.Low, false, "", ""},
		// PkgPath replaces the target; UNKNOWN is info.
		{"CVE-2000-0001", "vendor/django/METADATA", 1, findings.Info, false, "", ""},
	} {
		f := fs[i]
		if f.Title != w.title || f.Location.URI != w.uri || f.Location.StartLine != w.line || f.Severity != w.sev ||
			strings.HasSuffix(f.Message, DevNote) != w.dev || strings.Join(f.CWEs, ",") != w.cwes || f.HelpURI != w.help ||
			f.Family != "sca" || f.Sources[0].Plugin != "trivy" || f.Sources[0].RuleID != f.RuleID || f.Fingerprint == "" {
			t.Errorf("%d: %+v", i, f)
		}
	}
	if m := fs[0].Message; m != "Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21\nLink: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)" {
		t.Errorf("message %q", m)
	}
	// The dev and production copies are one issue at one place.
	if fs[2].Fingerprint != fs[3].Fingerprint {
		t.Error("dev and production copies have different fingerprints")
	}
}

// Without a UID, the first package with the same name and version decides.
func TestDevWithoutUID(t *testing.T) {
	doc := `{"SchemaVersion":2,"ArtifactName":"/target","Results":[{"Target":"yarn.lock","Packages":[{"Name":"a","Version":"1","Dev":true}],
"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","Severity":"HIGH"}]}]}`
	fs, err := ToFindings(strings.NewReader(doc), Options{Plugin: "trivy", Family: "sca"})
	if err != nil || len(fs) != 1 || !strings.HasSuffix(fs[0].Message, DevNote) {
		t.Fatalf("%+v %v", fs, err)
	}
}

// Trivy leaves Results out when it finds nothing.
func TestNothingFound(t *testing.T) {
	fs, err := ToFindings(strings.NewReader(`{"SchemaVersion":2,"ArtifactName":"/target"}`), Options{Plugin: "trivy", Family: "sca"})
	if err != nil || len(fs) != 0 {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not JSON":       `{`,
		"SARIF":          `{"version":"2.1.0","runs":[]}`,
		"schema 1":       `{"SchemaVersion":1,"ArtifactName":"x"}`,
		"no artifact":    `{"SchemaVersion":2}`,
		"no ID":          `{"SchemaVersion":2,"ArtifactName":"x","Results":[{"Target":"a","Vulnerabilities":[{"PkgName":"a"}]}]}`,
		"too large":      `{"SchemaVersion":2,"ArtifactName":"x","Results":[]}` + strings.Repeat(" ", MaxSize),
		"wrong type":     `{"SchemaVersion":"2","ArtifactName":"x"}`,
		"trailing value": `{"SchemaVersion":2,"ArtifactName":"x"} {}`,
	} {
		if _, err := ToFindings(strings.NewReader(doc), Options{Plugin: "trivy", Family: "sca"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ToFindings(strings.NewReader(sample), Options{Family: "sca"}); err == nil {
		t.Error("no plugin accepted")
	}
}

// fuzzSeed is a small report: Go minimizes each new input for up to 60 s by
// default, and with the 4 KB sample as the seed that minimizing took the
// whole run (measured 2026-11-23: 10 inputs in 30 s; with this seed and an
// empty cache, 6.1 and 6.8 million in two 30 s runs).
const fuzzSeed = `{"SchemaVersion":2,"ArtifactName":"/t","Results":[{"Target":"p","Packages":[{"Name":"a","Version":"1","Dev":true,"Identifier":{"UID":"u"},"Locations":[{"StartLine":5}]}],
"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","PkgIdentifier":{"UID":"u"},"InstalledVersion":"1","Severity":"HIGH","SeveritySource":"n","CVSS":{"n":{"V3Score":9.1}},"CweIDs":["CWE-1"]}]}]}`

func FuzzTrivy(f *testing.F) {
	f.Add([]byte(fuzzSeed))
	f.Fuzz(func(t *testing.T, b []byte) {
		fs, err := ToFindings(bytes.NewReader(b), Options{Plugin: "trivy", Family: "sca", MountPath: "/target"})
		if err != nil {
			return
		}
		for _, x := range fs {
			if x.RuleID == "" || x.Fingerprint == "" || x.Location.StartLine < 1 {
				t.Fatalf("finding %+v", x)
			}
		}
	})
}
