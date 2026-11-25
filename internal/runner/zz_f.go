// MEASUREMENT PROTOTYPE, NOT FOR MERGE (#86): what happens to the findings
// of a check stopped because the host stopped serving the app.
// SIEGEKIT_ZZ_F=f1 keeps them (ADR 0067's rule), f2 drops those whose
// message shows the block page's status and length (within 5%), f3 drops
// them all.
package runner

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

var zzShapeRe = regexp.MustCompile(`(\d{3}) (?:page )?\([^,]*, (-?\d+) bytes\)`)
var zzMsgRe = regexp.MustCompile(`answered (\d{3}) \((\d+) bytes`)

// ZZFilter applies SIEGEKIT_ZZ_F to the findings of a stopped check and
// says what it did.
func ZZFilter(reason string, fs []findings.Finding) ([]findings.Finding, string) {
	if !strings.Contains(reason, "the host stopped serving the app") {
		return fs, ""
	}
	switch os.Getenv("SIEGEKIT_ZZ_F") {
	case "f3":
		if len(fs) == 0 {
			return fs, ""
		}
		return nil, "; " + strconv.Itoa(len(fs)) + " finding(s) dropped (F3)"
	case "f2":
		m := zzShapeRe.FindStringSubmatch(reason)
		if m == nil {
			return fs, "; F2: no block shape in the reason, findings kept"
		}
		st, _ := strconv.Atoi(m[1])
		n, _ := strconv.Atoi(m[2])
		var out []findings.Finding
		dropped := 0
		for _, f := range fs {
			mm := zzMsgRe.FindStringSubmatch(f.Message)
			if mm != nil {
				fst, _ := strconv.Atoi(mm[1])
				fn, _ := strconv.Atoi(mm[2])
				d := fn - n
				if d < 0 {
					d = -d
				}
				if fst == st && d <= max(fn, n)/20 {
					dropped++
					continue
				}
			}
			out = append(out, f)
		}
		return out, "; " + strconv.Itoa(dropped) + " finding(s) matching the block page dropped (F2)"
	}
	return fs, ""
}
