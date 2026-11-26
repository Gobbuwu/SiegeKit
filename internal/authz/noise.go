package authz

import (
	"bytes"
	"regexp"
)

// Page noise (issue #95): a page can carry a value that is new in every
// answer, such as a Content-Security-Policy nonce (Next.js's CSP guide
// puts a fresh one on every script tag). Two answers of the same page then
// differ although nothing changed. The answers are compared word by word:
// the bytes between words must match, and so must every word outside the
// places where the page's two reads before a write already differed.

// reWord is a run of the bytes a nonce, a token or an ID is made of
// (base64 and URL-safe base64 included).
var reWord = regexp.MustCompile(`[A-Za-z0-9_+/=-]+`)

// pageWords splits a body into its words and the rest, with each word
// replaced by a zero byte.
func pageWords(b []byte) (rest []byte, ws [][]byte) {
	return reWord.ReplaceAll(b, []byte{0}), reWord.FindAll(b, -1)
}

// pageNoise compares A's two reads of a page before a write. ok is false
// when they cannot be lined up word by word (a different status or
// layout): then no change after the write can be told from noise. noise
// marks the words that differed; it is nil when the reads were the same.
func pageNoise(before, again Answer) (noise []bool, ok bool) {
	if before.Err != "" || again.Err != "" || before.Status != again.Status {
		return nil, false
	}
	if bytes.Equal(before.Body, again.Body) {
		return nil, true
	}
	r1, w1 := pageWords(before.Body)
	r2, w2 := pageWords(again.Body)
	if !bytes.Equal(r1, r2) || len(w1) != len(w2) {
		return nil, false
	}
	noise = make([]bool, len(w1))
	for i := range w1 {
		noise[i] = !bytes.Equal(w1[i], w2[i])
	}
	return noise, true
}

// changedFrom reports whether after differs from before outside the noise
// that pageNoise found.
func changedFrom(before Answer, noise []bool, after Answer) bool {
	if after.Status != before.Status {
		return true
	}
	if noise == nil {
		return !bytes.Equal(after.Body, before.Body)
	}
	r1, w1 := pageWords(before.Body)
	r2, w2 := pageWords(after.Body)
	if !bytes.Equal(r1, r2) || len(w1) != len(w2) || len(w1) != len(noise) {
		return true
	}
	for i := range w1 {
		if !noise[i] && !bytes.Equal(w1[i], w2[i]) {
			return true
		}
	}
	return false
}

// maxNoiseValues is how many different values sameButNoise lets differ.
const maxNoiseValues = 8

// tokenLike reports whether a word looks like a per-answer random value: at
// least 16 bytes with two of lower case, upper case and digits (a base64
// nonce, React's per-request IDs, a hex token). A name, a count or "true"
// is not one.
func tokenLike(w string) bool {
	if len(w) < 16 {
		return false
	}
	var lower, upper, digit bool
	for _, c := range w {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			n++
		}
	}
	return n >= 2
}

// sameButNoise reports whether two answers to the same sender are one page
// with fresh values or two: the same status, the same bytes between words,
// and the words that differ are random-looking values (tokenLike), at most
// maxNoiseValues of them, each replaced the same way wherever it appears.
// Next.js answers a DELETE, PUT or PATCH on a page's URL with the page,
// differing from a GET in its nonce (the gate's workspace page) and React's
// per-request IDs (Porchlet's, issue #95).
func sameButNoise(x, y Answer) bool {
	if x.Err != "" || y.Err != "" || x.Status != y.Status {
		return false
	}
	if bytes.Equal(x.Body, y.Body) {
		return true
	}
	if !linedUp(x, y) {
		return false
	}
	_, w1 := pageWords(x.Body)
	_, w2 := pageWords(y.Body)
	swap := map[string]string{}
	for i := range w1 {
		a, b := string(w1[i]), string(w2[i])
		if a == b {
			continue
		}
		if to, seen := swap[a]; seen {
			if to != b {
				return false
			}
			continue
		}
		if len(swap) == maxNoiseValues || !tokenLike(a) || !tokenLike(b) {
			return false
		}
		swap[a] = b
	}
	return true
}

// linedUp reports whether two answers have the same status and can be
// compared word by word: the same bytes between words and as many words.
func linedUp(x, y Answer) bool {
	if x.Err != "" || y.Err != "" || x.Status != y.Status {
		return false
	}
	r1, w1 := pageWords(x.Body)
	r2, w2 := pageWords(y.Body)
	return bytes.Equal(r1, r2) && len(w1) == len(w2)
}
