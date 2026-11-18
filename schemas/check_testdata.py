"""Validate schema test fixtures: every file in valid/ must pass, every file in invalid/ must fail.

Run: python3 -I schemas/check_testdata.py   (requires the `jsonschema` package)
Temporary check for M0; replaced by a Go test in M1.
"""
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

here = pathlib.Path(__file__).resolve().parent
schema = json.loads((here / "plugin-manifest.schema.json").read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

failures = 0
for expect_valid, folder in ((True, "valid"), (False, "invalid")):
    for path in sorted((here / "testdata" / folder).glob("*.json")):
        errors = list(validator.iter_errors(json.loads(path.read_text())))
        ok = (not errors) if expect_valid else bool(errors)
        print(f"{'PASS' if ok else 'FAIL'}  {folder}/{path.name}" + ("" if expect_valid or not errors else f"  ({errors[0].message[:70]})"))
        failures += not ok
sys.exit(1 if failures else 0)
