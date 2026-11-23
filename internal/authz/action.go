package authz

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// actionWords name an action that changes data. A GET whose path or action
// parameter holds one of them is not replayed (ADR 0048): a GET is not
// always safe. Replaying a recorded Juice Shop session changed account B's
// password (GET /rest/user/change-password) and last-login IP (GET
// /rest/saveLoginIp), measured 2026-11-21. Nouns that read pages more often
// than they act (order, archive, sort, login, new, read, set, star, watch,
// close, send) are left out: they skipped read pages in the measurement.
var actionWords = setOf(`accept ack acknowledge activate add approve ban block buy cancel change checkout claim confirm
create deactivate decline del delete deploy destroy disable dismiss downvote drop edit enable erase exec execute follow
generate grant import insert install invite join kill lock logoff logout migrate modify move mute patch pay publish
purchase purge rebuild redeem redo refund regenerate register reject remove rename reopen reorder reset restart restore
retry revert revoke rotate save setup signout signup submit subscribe toggle transfer trash trigger unarchive unban
unblock undo unfollow uninstall unlike unlock unmute unpublish unstar unsubscribe unwatch update upload upvote verify vote`)

// actionParams are query parameters whose value names the action, as in
// "?action=delete".
var actionParams = setOf("action do cmd op operation")

// reSecretParam matches query parameter names that carry a password or a
// secret: a GET that sends one acts on the account.
var reSecretParam = regexp.MustCompile(`(?i)pass(word|wd)?|pwd|secret`)

func setOf(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// words splits s into lower-case words of letters at every other character
// and at camelCase boundaries: "saveLoginIp" and "change-password" give
// save, login, ip and change, password.
func words(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		if r > unicode.MaxASCII || !unicode.IsLetter(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]) {
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

// ActionReason says why a GET to p (path and query) is not replayed: the
// action word in its path or action parameter, or the password or secret
// parameter it sends. It is "" for a request that is replayed.
func ActionReason(p string) string {
	pathPart, query, _ := strings.Cut(p, "?")
	for _, seg := range strings.Split(pathPart, "/") {
		if u, err := url.PathUnescape(seg); err == nil {
			seg = u
		}
		for _, w := range words(seg) {
			if actionWords[w] {
				return "its path names the action \"" + w + "\""
			}
		}
	}
	q, _ := url.ParseQuery(query)
	for _, k := range slices.Sorted(maps.Keys(q)) { // a map's order changes each run
		vs := q[k]
		if reSecretParam.MatchString(k) {
			return "it sends the parameter \"" + k + "\""
		}
		if actionParams[strings.ToLower(k)] {
			for _, v := range vs {
				for _, w := range words(v) {
					if actionWords[w] {
						return "its parameter " + k + " names the action \"" + w + "\""
					}
				}
			}
		}
	}
	return ""
}
