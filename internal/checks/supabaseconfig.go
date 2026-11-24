package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// supabaseAuthConfig reads the Supabase CLI's supabase/config.toml for weak
// Supabase Auth settings (ADR 0064 item 7). The file configures the local
// stack and, with "supabase config push", a hosted project, so the findings
// are low or info: a hosted project's own settings may differ. Only values
// written in the file count; a missing key is left to Supabase's default.
//
// The file is read line by line: [section] headers and key = value pairs,
// which is all these keys use. Not reported: an empty password_requirements,
// because NIST SP 800-63B-4 section 3.1.1.2 says verifiers "SHALL NOT impose
// other composition rules".
var (
	reTOMLSection = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9_.\-]+)\s*\]\s*(?:#.*)?$`)
	reTOMLKey     = regexp.MustCompile(`^\s*([A-Za-z0-9_\-]+)\s*=\s*([^#]*?)\s*(?:#.*)?$`)
)

// minPasswordLength is NIST SP 800-63B-4's floor for passwords used only
// with a second factor ("a minimum of eight characters"); single-factor
// passwords need 15.
const minPasswordLength = 8

func supabaseAuthConfig(rel string, data []byte) []findings.Finding {
	var out []findings.Finding
	section := ""
	for i, l := range strings.Split(string(data), "\n") {
		if g := reTOMLSection.FindStringSubmatch(l); g != nil {
			section = g[1]
			continue
		}
		g := reTOMLKey.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		key, val := section+"."+g[1], strings.Trim(g[2], `"'`)
		loc := findings.Location{URI: rel, StartLine: i + 1}
		switch key {
		case "auth.minimum_password_length":
			if n, err := strconv.Atoi(val); err == nil && n < minPasswordLength {
				out = append(out, authConfigFinding("supabase-auth-short-passwords", "Supabase Auth accepts short passwords", findings.Low, loc,
					fmt.Sprintf("minimum_password_length = %d lets users choose passwords shorter than 8 characters, below NIST SP 800-63B-4's minimum even for passwords used with a second factor (15 for passwords used alone). Set it to at least 8, better 15, and turn on leaked-password protection in the hosted project.", n),
					"CWE-521"))
			}
		case "auth.email.enable_confirmations":
			if val == "false" {
				out = append(out, authConfigFinding("supabase-auth-email-unconfirmed", "Supabase Auth signs users in without confirming their email", findings.Info, loc,
					"enable_confirmations = false lets anyone sign up with an email address they do not own and use the account at once. This is the Supabase CLI's default for local development; make sure the hosted project confirms emails (Authentication > Sign In / Providers > Confirm email).",
					"CWE-287"))
			}
		case "auth.email.double_confirm_changes":
			if val == "false" {
				out = append(out, authConfigFinding("supabase-auth-email-change-unconfirmed", "Supabase Auth changes a user's email without confirming the old address", findings.Low, loc,
					"double_confirm_changes = false lets an email change go through with a confirmation sent only to the new address, so someone holding a stolen session can move the account to their own email and lock the owner out. Set it to true.",
					"CWE-287"))
			}
		}
	}
	return out
}

func authConfigFinding(id, title string, sev findings.Severity, loc findings.Location, msg, cwe string) findings.Finding {
	return findings.Finding{RuleID: id, Title: title, Message: msg, Severity: sev, CWEs: []string{cwe}, Location: loc}
}
