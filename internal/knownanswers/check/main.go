// Command check compares a SiegeKit report with a fixture's known answer
// (ADR 0039). CI runs it after each gate scan:
//
//	go run ./internal/knownanswers/check -answers FILE -report report.json [-observed OUT]
//
// It exits 1 when a check finds or does less (or more) than its answer, and
// prints the answers not met yet. -observed writes what the run showed, in
// the answer format, for review when a pin changes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Gobbuwu/SiegeKit/internal/knownanswers"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

func main() {
	answers := flag.String("answers", "", "known-answer file")
	rep := flag.String("report", "", "report.json of the run")
	observed := flag.String("observed", "", "write what the run showed here, as an answer file")
	flag.Parse()
	if err := run(*answers, *rep, *observed); err != nil {
		fmt.Fprintln(os.Stderr, "known answers:", err)
		os.Exit(1)
	}
}

func run(answersPath, reportPath, observedPath string) error {
	// The run's answer is written even when the answer file is missing or
	// broken, so a new fixture's first answer can be measured.
	a, loadErr := knownanswers.Load(answersPath)
	b, err := os.ReadFile(reportPath) // #nosec G304 -- a path from CI's own workflow
	if err != nil {
		return err
	}
	var r report.Run
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("%s: %w", reportPath, err)
	}
	eng, err := knownanswers.EngineOf(&r)
	if err != nil {
		return fmt.Errorf("%s: %w", reportPath, err)
	}
	if r.Environment == nil {
		r.Environment = &report.Environment{}
	}
	if observedPath != "" {
		fixture := ""
		if a != nil {
			fixture = a.Fixture
		}
		obs := knownanswers.AnswerFrom(fixture, "run on "+r.Environment.String()+", "+r.Started.UTC().Format("2006-01-02"), &r, a)
		out, err := json.MarshalIndent(obs, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(observedPath, append(out, '\n'), 0o600); err != nil {
			return err
		}
	}
	if loadErr != nil {
		return loadErr
	}
	res := knownanswers.Compare(a, &r, eng)
	fmt.Printf("Known answers for %s on %s\n", a.Fixture, r.Environment)
	for _, g := range res.NotMetYet {
		fmt.Println("  not met yet:", g)
	}
	for _, u := range res.Unstable {
		fmt.Println("  unstable:", u)
	}
	for _, f := range res.Failures {
		fmt.Println("  FAIL", f)
	}
	if len(res.Failures) > 0 {
		return fmt.Errorf("%d known answers not met", len(res.Failures))
	}
	fmt.Println("  every check met its known answer")
	return nil
}
