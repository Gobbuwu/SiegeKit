package testpath

import "testing"

func TestIsTest(t *testing.T) {
	for rel, want := range map[string]bool{
		// Porchlet's pgTAP probe (SK-4) and Supabase's own layout.
		"supabase/tests/database/000_baseline.test.sql": true,
		"supabase/tests/x.sql":                          true,
		"db/checks.test.sql":                            true,
		"supabase/migrations/001_init.sql":              false,
		"supabase/seed.sql":                             false,
		// The folders and names weak-passwords and the route reader used.
		"test/a.yml": true, "Tests/a.yml": true, "pkg/testdata/a.go": true, "fixtures/u.json": true,
		"src/__tests__/a.js": true, "spec/models/user_spec.rb": true, "e2e/fixtures.ts": true,
		"e2e-tests/cypress/x.js": true, "App.Tests/Config.cs": true, "AppIntegrationTests/a.cs": true,
		"src/a.test.ts": true, "src/a.spec.jsx": true, "src/a.test.mjs": true, "src/a.spec.cts": true,
		"a_test.go": true, "a_test.py": true, "test_a.py": true, "UserTest.java": true, "UserTests.cs": true,
		// Not tests.
		"src/latest.ts": false, "src/contest/a.go": false, "src/testing.go": false, "attest.py": false,
		"spectrum/a.js": false, "src/a.testing.js": false, "e2e-tests/run.go": false, "README.md": false,
	} {
		if got := IsTest(rel); got != want {
			t.Errorf("IsTest(%q) = %v, want %v", rel, got, want)
		}
	}
}
