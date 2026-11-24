// Package testpath decides whether a repository path holds tests: the one
// definition every static reader shares (ADR 0064 item 1), so that no two
// checks disagree on what a test is. Test code and fixtures are never
// deployed, so rules about deployed behaviour must not read them.
package testpath

import (
	"path"
	"regexp"
	"strings"
)

// dirs are folder names that hold tests or test data in common layouts:
// test/ and tests/ (most languages, and Supabase's pgTAP tests in
// supabase/tests), Go's testdata/, Jest's __tests__/, Ruby's spec/,
// fixtures/, and end-to-end suites (e2e/, cypress/).
var dirs = map[string]bool{
	"test": true, "tests": true, "testdata": true, "fixtures": true, "__tests__": true,
	"spec": true, "e2e": true, "cypress": true,
}

// .NET test projects: Foo.Tests, FooUnitTests, FooIntegrationTests.
var dirSuffixes = []string{".tests", "unittests", "functionaltests", "integrationtests"}

// files are test files by name: foo.test.ts, foo.spec.jsx, foo.test.sql
// (pgTAP), foo_test.go, foo_test.py, test_foo.py, FooTest.java,
// FooTests.cs, foo_spec.rb.
var files = regexp.MustCompile(`(\.(spec|test)\.([mc]?[jt]sx?|sql)$|_test\.(go|py)$|^test_.*\.py$|Tests?\.(java|kt|php|cs)$|_spec\.rb$)`)

// IsTestDir reports whether a folder with this name holds tests.
func IsTestDir(name string) bool {
	name = strings.ToLower(name)
	if dirs[name] {
		return true
	}
	for _, s := range dirSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// IsTestFile reports whether a file with this base name is a test.
func IsTestFile(base string) bool {
	return files.MatchString(base)
}

// IsTest reports whether the slash-separated relative path rel is a test
// file or lies in a test folder.
func IsTest(rel string) bool {
	if IsTestFile(path.Base(rel)) {
		return true
	}
	for _, d := range strings.Split(path.Dir(rel), "/") {
		if IsTestDir(d) {
			return true
		}
	}
	return false
}
