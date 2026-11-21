package main

import (
	"fmt"
	"os"
	"testing"
)

// TestMain makes every scan in these tests fail when a check is skipped
// with no valid cause (ADR 0041).
func TestMain(m *testing.M) {
	badCause = func(ids []string) { panic(fmt.Sprintf("skipped with no valid cause: %v", ids)) }
	os.Exit(m.Run())
}
