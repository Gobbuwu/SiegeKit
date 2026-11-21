package docs_test

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/docs"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

// TestAgentsGuideListsEveryField keeps the guide in step with report.json:
// every JSON field an assistant can read is named in it.
func TestAgentsGuideListsEveryField(t *testing.T) {
	var b bytes.Buffer
	if err := report.WriteJSON(&b, &report.Run{}); err != nil || !strings.Contains(b.String(), `"schemaVersion": 1`) {
		t.Fatalf("report.json has no schemaVersion 1: %v", err)
	}
	if !strings.Contains(docs.Agents, "currently 1") {
		t.Error("guide does not state the current schemaVersion")
	}
	for _, v := range []any{report.Run{}, report.Environment{}, report.Engine{}, report.Comparison{}, report.PluginResult{}, findings.Finding{}, findings.Location{}, findings.Source{}} {
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
			if name != "" && name != "-" && !strings.Contains(docs.Agents, "`"+name+"`") {
				t.Errorf("%s.%s (%q) is not described in agents.md", rt.Name(), rt.Field(i).Name, name)
			}
		}
	}
}

// TestAgentsGuideListsEveryCause keeps the guide's list of skip causes
// complete (ADR 0041).
func TestAgentsGuideListsEveryCause(t *testing.T) {
	for _, c := range report.Causes {
		if !strings.Contains(docs.Agents, "`"+string(c)+"`") {
			t.Errorf("cause %q is not described in agents.md", c)
		}
	}
}

func TestEmbeddedGuideIsCurrent(t *testing.T) {
	b, err := os.ReadFile("agents.md")
	if err != nil || string(b) != docs.Agents {
		t.Fatalf("embedded guide differs from agents.md: %v", err)
	}
}
