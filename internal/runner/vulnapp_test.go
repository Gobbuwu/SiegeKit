package runner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// vulnApp is SiegeKit's own deliberately vulnerable web app for the active
// tests (owner decision 2026-11-19: our own fixture for tests, so each issue
// is known). Every issue is listed in vulnAppIssues with the rule that
// must find it. It runs in the test process; nothing here is shipped.
func vulnApp() http.Handler {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, body string) {
		// No X-Frame-Options, Content-Security-Policy or
		// X-Content-Type-Options; the Server header leaks a version.
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><html><head><title>Shop</title></head><body>%s</body></html>", body)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Session cookie without HttpOnly or SameSite.
		w.Header().Add("Set-Cookie", "session=4f2a9c1e7b; Path=/")
		page(w, `<h1>Shop</h1>
<a href="/search?q=shoes">Search</a>
<a href="/item?id=1">Item 1</a>
<a href="/file?name=terms.txt">Terms</a>
<form action="/search" method="get"><input name="q" value="hat"><input type="submit"></form>`)
	})
	// Reflected cross-site scripting: the query is echoed unescaped.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>Results for "+r.URL.Query().Get("q")+"</p>")
	})
	// SQL injection: a quote in id produces a database error message, as
	// a string-built query would. The status stays 200 so the egress
	// proxy's server-error stop does not end the scan.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, `'"`) {
			page(w, "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"+strings.ReplaceAll(id, "<", "&lt;")+"' at line 1</p>")
			return
		}
		page(w, "<p>Item "+strings.ReplaceAll(id, "<", "&lt;")+": a hat.</p>")
	})
	// Path traversal: names reaching outside the folder return system files.
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "etc/passwd") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		page(w, "<pre>Terms of use.</pre>")
	})
	// An exposed git config and an exposed .env file, served as plain text
	// (no secrets: the values are placeholders).
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "APP_NAME=shop\nAPP_ENV=local\n")
	})
	// PUT stores the file and GET serves it back, as a misconfigured WebDAV
	// server would.
	var mu sync.Mutex
	stored := map[string][]byte{}
	mux.HandleFunc("/testing-put.txt", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			stored[r.URL.Path] = b
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			b, ok := stored[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write(b)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

// vulnAppIssues maps each planted issue to the rule (ZAP rule ID or Nuclei
// template ID) that must report it, per plugin.
var vulnAppIssues = map[string]map[string]string{
	"zap": {
		"10020": "missing anti-clickjacking header",
		"10021": "missing X-Content-Type-Options",
		"10038": "missing Content-Security-Policy",
		"10010": "cookie without HttpOnly",
		"10054": "cookie without SameSite",
		"10036": "Server header leaks a version",
	},
	"zap-active": {
		"40012": "reflected cross-site scripting in /search",
		"40018": "SQL injection in /item",
		"6":     "path traversal in /file",
	},
	"nuclei": {
		"http-missing-security-headers": "missing security headers",
		"git-config":                    "exposed /.git/config",
		"laravel-env":                   "exposed /.env",
	},
	"nuclei-intrusive": {
		"put-method-enabled": "PUT uploads a file that the server then serves",
	},
}
