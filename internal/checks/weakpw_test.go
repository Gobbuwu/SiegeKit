package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// TestCommonPasswordsPinned checks the shipped SecLists file is the pinned
// one, byte for byte (ADR 0034).
func TestCommonPasswordsPinned(t *testing.T) {
	sum := sha256.Sum256(commonPasswords)
	if got := hex.EncodeToString(sum[:]); got != "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce" || len(commonPasswords) != 73026 {
		t.Errorf("sha256 %s, %d bytes", got, len(commonPasswords))
	}
	if !weakList["123456"] || !weakList["changeme"] || weakList[""] {
		t.Error("weak list not loaded")
	}
}

type hitWant struct {
	line int
	skip string
}

func TestWeakHits(t *testing.T) {
	for _, tc := range []struct {
		name, file, body string
		want             []hitWant
	}{
		{"env file", ".env", "DB_PASSWORD=admin123\nADMIN_PASSWORD=changeme\nAPI_URL=x\n", []hitWant{{1, ""}, {2, ""}}},
		{"compose list and map", "compose.yaml", "services:\n  db:\n    environment:\n      - MYSQL_PASSWORD=p@ssw0rd\n      POSTGRES_PASSWORD: \"postgres\"\n", []hitWant{{4, ""}, {5, ""}}},
		{"dockerfile", "Dockerfile", "FROM x\nENV DB_PASSWORD=secret\nARG ADMIN_PASS=hunter2\n", []hitWant{{2, ""}, {3, ""}}},
		{"json", "config.json", `{"db": {"password": "Summer2024!"}}`, []hitWant{{1, ""}}},
		{"xml element and attribute", "app.xml", "<cfg>\n<password>tomcat</password>\n<user name=\"a\" password=\"s3cret\"/>\n</cfg>\n", []hitWant{{2, ""}, {3, ""}}},
		{"sql", "seed.sql", "CREATE USER 'app'@'%' IDENTIFIED BY 'app';\n", []hitWant{{1, ""}}},
		// SK-5: the planted Supabase seed of the Porchlet run, and its other shapes.
		{"sql crypt seed", "supabase/seed.sql", "insert into auth.users (email, encrypted_password)\nvalues ('a@x.io', crypt('password123', gen_salt('bf')));\n", []hitWant{{2, ""}}},
		{"sql crypt schema-qualified", "supabase/seed.sql", "select extensions.crypt( 'qwerty' , extensions.gen_salt('bf'));\nselect CRYPT('admin',gen_salt('md5'));\n", []hitWant{{1, ""}, {2, ""}}},
		{"sql crypt strong or not literal", "supabase/seed.sql", "select crypt('Xk29!fqLw0pZ8sTq', gen_salt('bf'));\nselect crypt(new.password, gen_salt('bf'));\nselect crypt(p_input, stored_hash) = stored_hash;\n", nil},
		{"sql crypt in a pgTAP test", "supabase/tests/database/users.test.sql", "select crypt('password123', gen_salt('bf'));\n", []hitWant{{1, skipTest}}},
		{"crypt outside sql", "a.js", "const h = crypt('password123', salt)\n", nil},
		{"url in any text file", "notes.cfg2", "url = postgres://app:secret@db/app\n", []hitWant{{1, ""}}},
		{"python code", "app/settings.py", "password = \"hunter2\"\n", []hitWant{{1, ""}}},
		{"javascript object", "seed.js", "users.insert({ name: 'a', password: 'Admin_123' })\n", []hitWant{{1, ""}}},
		{"same as user name", "db.yml", "username: nextcloud\npassword: nextcloud-is-long-enough\nmysql_password: nextcloud\n", []hitWant{{3, ""}}},
		{"same as key name", "c.properties", "druid.pass=druid\n", []hitWant{{1, ""}}},
		{"long random value", ".env", "DB_PASSWORD=Xk29!fqLw0pZ8sTq\n", nil},
		{"variable references", ".env", "A_PASSWORD=${DB_PASSWORD}\nB_PASSWORD=$DB_PASSWORD\nC_PASSWORD={{ .Values.pw }}\nD_PASSWORD=<%= ENV['X'] %>\n", nil},
		{"code variable reference", "a.js", "const password = process.env.PW\nconst pw = getenv('PW')\n", nil},
		{"not passwords", "a.yml", "password: true\npassword_min_length: 12\nbypass: admin\npassage: x\npassword:\n  nested: 1\nversion_password: 1.2.1\npassword: |\n", nil},
		{"format string", "a.py", "password = \"%s\"\n", nil},
		{"placeholders", "a.go", "body := `{\"password\":\"{password}\"}`\nx := \"password=<your-password>\"\n", nil},
		{"key inside a longer string", "Example.java", "addCriterion(\"password =\", value, \"password\");\n", nil},
		{"test folder", "src/test/java/A.java", "String password = \"secret\";\n", []hitWant{{1, skipTest}}},
		{"test file name", "web/login.spec.ts", "const password = 'pass';\n", []hitWant{{1, skipTest}}},
		{"dotnet test project", "Nop.Tests/Validators/V.cs", "p.Password = \"nop123\";\n", []hitWant{{1, skipTest}}},
		{"translation file", "src/i18n/de.json", `{"password": "Passwort"}`, []hitWant{{1, skipI18n}}},
		{"documentation", "docs/setup.yml", "password: admin\n", []hitWant{{1, skipDoc}}},
		{"markdown", "README.md", "Use postgres://user:pass@localhost/db\n", []hitWant{{1, skipDoc}}},
		{"template", "config.yml.example", "password: changeme\n", []hitWant{{1, skipTemplate}}},
		{"env template", ".env.example", "DB_PASSWORD=changeme\n", []hitWant{{1, skipTemplate}}},
		{"comment line", "a.rb", "# user.password = \"vr00m\"\nx = 1\n", []hitWant{{1, skipComment}}},
		{"python docstring", "a.py", "def f():\n    \"\"\"Example:\n    password = \"hunter2\"\n    \"\"\"\n", []hitWant{{3, skipComment}}},
		{"after a docstring", "a.py", "\"\"\"doc\"\"\"\npassword = \"hunter2\"\n", []hitWant{{2, ""}}},
		{"ruby =begin", "a.rb", "=begin\npassword = \"vr00m\"\n=end\npassword = \"vr00m\"\n", []hitWant{{2, skipComment}, {4, ""}}},
		{"commented config is not read", "a.yml", "# password: admin\n", nil},
		{"one hit per line and value", "a.yml", "password: \"admin\"\n", []hitWant{{1, ""}}},
		{"binary", "a.json", "\x00password: admin\n", nil},
		{"other text file: urls only", "a.txt2", "password = admin\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []hitWant
			for _, h := range weakHits(tc.file, []byte(tc.body)) {
				got = append(got, hitWant{h.line, h.skip})
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWeakHitsValueGrammar checks that each format reads a value by its
// own grammar (#93): ":=" is one separator, and SQL, Terraform and TOML
// take only quoted literals, since an unquoted right-hand side there is an
// expression.
func TestWeakHitsValueGrammar(t *testing.T) {
	type hit struct {
		line  int
		value string
	}
	for _, tc := range []struct {
		name, file, body string
		want             []hit
	}{
		// Porchlet's two lines: an empty literal clears a hash column.
		{"plpgsql clears a column", "supabase/migrations/1_x.sql", "begin\n    new.encrypted_password := '';\n    return new;\nend;\n", nil},
		{"plpgsql literal", "a.sql", "  v_pass := 'abc';\n", []hit{{1, "abc"}}},
		{"plpgsql expressions", "a.sql", "v_password := gen_random_uuid()::text;\nnew.encrypted_password := crypt(new.password, gen_salt('bf'));\nv_pass := p_pass;\n", nil},
		{"sql = literal", "a.sql", "update users set\n  password = 'admin',\n  name = 'x';\n", []hit{{2, "admin"}}},
		{"sql trailing comments", "a.sql", "  password = 'admin'; -- seed\n  pass = 'root' # mysql\n", []hit{{1, "admin"}, {2, "root"}}},
		{"sql double quotes are identifiers", "a.sql", "select * from users where\n  password = \"password\";\nselect 1 where password = \"pass\";\n", nil},
		{"sql comment", "a.sql", "-- password := 'admin';\n", nil},
		{"sql still reads IDENTIFIED BY", "a.sql", "CREATE USER 'app'@'%' IDENTIFIED BY 'app';\n", []hit{{1, "app"}}},
		{"terraform reference", "main.tf", "  password = var.pw\n  admin_password = random_password.db.result\n", nil},
		{"terraform literal", "main.tf", "  administrator_login_password = \"Aa12345678\"\n", []hit{{1, "Aa12345678"}}},
		{"terraform interpolation", "vars.tfvars", "db_password = \"${var.pw}\"\n", nil},
		{"toml literals", "config.toml", "password = \"admin\"\n[db]\npass = 'root'\n", []hit{{1, "admin"}, {3, "root"}}},
		{"toml non-strings", "config.toml", "password = admin\npassword_len = 1234\npassword = { file = \"x\" }\n", nil},
		{"toml := literal", "config.toml", "password := \"admin\"\n", []hit{{1, "admin"}}},
		{":= in a key = value file", ".env", "DB_PASSWORD := admin\nPASS:=root\n", []hit{{1, "admin"}, {2, "root"}}},
		{":= with nothing after it", "a.yml", "password :=\npassword: =\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []hit
			for _, h := range weakHits(tc.file, []byte(tc.body)) {
				got = append(got, hit{h.line, h.value})
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWeakReason(t *testing.T) {
	for v, want := range map[string]string{
		"123456":          "most common",
		"Admin":           "most common",
		"nextcloud":       "user name",
		"druid":           "name it is set for",
		"Aa12345678":      "shorter than 12",
		"Xk29!fqLw0pZ8sT": "",
	} {
		got := weakReason(v, "druid.password", map[string]bool{"nextcloud": true})
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%q: %q, want %q", v, got, want)
		}
	}
}

func TestRunWeakPasswords(t *testing.T) {
	root := tree(t, map[string]string{
		".env":                  "DB_PASSWORD=admin123\n",
		"compose.yaml":          "    environment:\n      - POSTGRES_PASSWORD=postgres\n",
		"tests/fixture.yml":     "password: admin\n",
		"README.md":             "Connect to postgres://app:secret@localhost/app\n",
		"node_modules/x/a.json": `{"password": "admin"}`,
		"dist/app.js":           "password = 'admin'\n",
		"package-lock.json":     `{"password": "admin"}`,
	})
	o, err := weakPasswords.Run(context.Background(), root)
	fs, result := o.Findings, o.Result
	if err != nil {
		t.Fatal(err)
	}
	if result != "2 weak password(s) reported; 2 not reported: 1 in tests, 1 in documentation" {
		t.Errorf("result %q", result)
	}
	if len(fs) != 2 {
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Severity != findings.Medium || !slices.Equal(f.CWEs, []string{"CWE-521", "CWE-798"}) || f.Family != "secrets" || f.Fingerprint == "" || f.Sources[0].Plugin != weakPasswordsID {
			t.Errorf("%+v", f)
		}
		if strings.Contains(f.Message, "admin123") || strings.Contains(f.Message, "=postgres") {
			t.Errorf("value not masked: %s", f.Message)
		}
	}
	if fs[0].Location != (findings.Location{URI: ".env", StartLine: 1}) || !strings.Contains(fs[0].Message, "admi****") {
		t.Errorf("%+v", fs[0])
	}
	if o, _ := weakPasswords.Run(context.Background(), tree(t, nil)); o.Result != "0 weak password(s) reported" {
		t.Errorf("empty: %q", result)
	}
}

// TestWeakHitsLargeFile runs a file with many hits. Linear time was
// measured by hand (ADR 0034, M2 record), not here: a timing bound is not
// reliable under -race on shared CI runners.
func TestWeakHitsLargeFile(t *testing.T) {
	var b strings.Builder
	for i := 0; b.Len() < 256<<10; i++ {
		fmt.Fprintf(&b, "password = \"a%d\" \"\"\"\n", i)
	}
	if n := len(weakHits("big.py", []byte(b.String()))); n != 11386 {
		t.Errorf("%d hits", n)
	}
}

func FuzzWeakHits(f *testing.F) {
	f.Add("a.yml", "password: admin\n# x\nurl: http://u:p@h/\n")
	f.Add("a.py", "\"\"\"\npassword = 'x'\n\"\"\"\n=begin\n=end\npassword='y'")
	f.Add(".env", "export DB_PASS=\"x\" # c\n- A_PWD='y'\n")
	f.Fuzz(func(t *testing.T, name, body string) {
		lines := strings.Count(body, "\n") + 1
		for _, h := range weakHits(name, []byte(body)) {
			if h.line < 1 || h.line > lines || h.value == "" || h.reason == "" {
				t.Fatalf("bad hit %+v", h)
			}
		}
	})
}
