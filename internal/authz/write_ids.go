package authz

import (
	"net/url"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/webform"
)

// An ID's value alone does not say which object it names: per-table
// numbers collide. In a browser recording on Juice Shop, A's basket and
// A's new address were both 8, and the checkout POST /rest/basket/8/checkout
// carries "addressId": "8". Replacing every 8 with the address copy's ID
// sent the replays to a basket that does not exist, and a real high was
// missed (measured 2026-11-22). So each place an ID sits gets a noun, the
// kind of object it names, and a copy's ID replaces the places whose noun
// is the create's (ADR 0054).

// nounOf is the kind of object a name stands for: its last word that is
// not an ID word, in lower case ("BasketId" and "/api/Baskets" give
// "basket" and "baskets"). Empty when the name has no such word ("id",
// "_id"). Nouns are compared with nounsMatch.
func nounOf(s string) string {
	ws := webform.Words(s)
	for i := len(ws) - 1; i >= 0; i-- {
		w := ws[i]
		if idRank(w) >= 0 || w == "ids" || reID.MatchString(w) {
			continue
		}
		return w
	}
	return ""
}

// nounsMatch reports whether two nouns are one word, singular or plural:
// "basket" and "baskets", "address" and "addresses" and Juice Shop's
// "addresss", "category" and "categories", "type" and "types".
func nounsMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	for _, x := range nounForms(a) {
		for _, y := range nounForms(b) {
			if x == y {
				return true
			}
		}
	}
	return false
}

func nounForms(w string) []string {
	out := []string{w, strings.TrimSuffix(w, "s"), strings.TrimSuffix(w, "es"), strings.TrimRight(w, "s")}
	if strings.HasSuffix(w, "ies") {
		out = append(out, strings.TrimSuffix(w, "ies")+"y")
	}
	return out
}

// createNoun is the kind of object a create makes: the last word of a
// method call's name (createTask: "task", as sameNoun reads it), else the
// last path segment that is not an ID (POST /api/Addresss/: "addresss").
func createNoun(c Create) string {
	if c.RPCMethod != "" {
		return nounOf(c.RPCMethod)
	}
	segs := strings.Split(strings.Trim(pathOf(c.Path), "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s, err := url.PathUnescape(segs[i])
		if err != nil || s == "" || reID.MatchString(s) {
			continue
		}
		return nounOf(s)
	}
	return ""
}

// segNouns gives each path segment of p the noun of the nearest segment
// before it that is not an ID: in /rest/basket/8/checkout, 8 is a basket.
func segNouns(segs []string) []string {
	out := make([]string, len(segs))
	last := ""
	for i, seg := range segs {
		out[i] = last
		if s, err := url.PathUnescape(seg); err == nil && s != "" && !reID.MatchString(s) {
			last = nounOf(s)
		}
	}
	return out
}

// idNouns are the nouns of the places in w that hold value: path segments,
// query values (the key's noun) and body values at ID-named keys (the
// key's noun; a method call's params only). A place with no noun ("id")
// gives "".
func (w Write) idNouns(value string) []string {
	var out []string
	p, q, _ := strings.Cut(w.Path, "?")
	segs := strings.Split(p, "/")
	nouns := segNouns(segs)
	for i, seg := range segs {
		if s, err := url.PathUnescape(seg); err == nil && s == value {
			out = append(out, nouns[i])
		}
	}
	if vals, err := url.ParseQuery(q); err == nil {
		for k, vs := range vals {
			for _, v := range vs {
				if v == value {
					out = append(out, nounOf(k))
				}
			}
		}
	}
	if scope, _, ok := idScope(w.Body); ok {
		walkIDKeys(scope, 0, func(_ map[string]any, k, s string) {
			if s == value {
				out = append(out, nounOf(k))
			}
		})
	} else if strings.HasPrefix(strings.ToLower(w.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(string(w.Body)); err == nil {
			for k, vs := range vals {
				for _, x := range vs {
					if idKey(k) && x == value {
						out = append(out, nounOf(k))
					}
				}
			}
		}
	}
	return out
}

// namesAs reports whether some place in w holds value under noun.
func (w Write) namesAs(value, noun string) bool {
	for _, n := range w.idNouns(value) {
		if nounsMatch(n, noun) {
			return true
		}
	}
	return false
}

// replacer returns whether a place of w holding value, with noun place,
// names the object of kind noun: always when either noun is unknown or
// they match, and, when no place in w names value as noun, every
// place (a key the create's noun does not match, such as "msgId" for
// chat.sendMessage, still names the copy's object).
func (w Write) replacer(value, noun string) func(place string) bool {
	named := w.namesAs(value, noun)
	return func(place string) bool {
		return noun == "" || place == "" || nounsMatch(place, noun) || !named
	}
}
