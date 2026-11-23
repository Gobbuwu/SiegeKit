package runner

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// vulnAppSpec is the OpenAPI spec of the app's small JSON API, served at
// /openapi.json. Its operations are relative to the server URL /api.
const vulnAppSpec = `{"openapi":"3.0.3","info":{"title":"Shop API","version":"1"},"servers":[{"url":"/api"}],
"paths":{"/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer","minimum":1}}],
"responses":{"200":{"description":"The item","content":{"application/json":{"schema":{"type":"object","required":["id","name"],"properties":{"id":{"type":"integer"},"name":{"type":"string"}}}}}},
"404":{"description":"No such item"}}}}}}`

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
<form action="/search" method="get"><input name="q" value="hat"><input type="submit"></form>
<script src="/static/app.js"></script><script src="/static/vendor.js"></script>`)
	})
	// Keys in served files: a token in a script and a cloud key in its
	// source map. They are assembled at run time so this repository never
	// contains a string that secret scanners would flag.
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprintf(w, "const api = {token: %q};\n//# sourceMappingURL=app.js.map\n", servedToken)
	})
	mux.HandleFunc("/static/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":3,"sources":["src/config.js"],"sourcesContent":["export const awsKey = '%s';"],"mappings":""}`, servedCloudKey)
	})
	// A source map that its script does not name, next to it with ".map"
	// added, as webpack's hidden-source-map writes it (ADR 0046).
	mux.HandleFunc("/static/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprint(w, "var vendor = 1;\n")
	})
	mux.HandleFunc("/static/vendor.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":3,"sources":["src/vendor.js"],"sourcesContent":["export const vendor = 1;"],"mappings":"AAAA"}`)
	})
	// XML external entities (ADR 0047): POST /api/import reads the XML it
	// is sent and resolves each file:// entity its DOCTYPE declares, as a
	// parser with external entities on would, then echoes the document.
	// Go's encoding/xml never resolves entities, so this is done by hand.
	// The page never sends XML: only a recorded request reaches it.
	mux.HandleFunc("/api/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		doc := string(b)
		for _, m := range reXMLEntity.FindAllStringSubmatch(doc, 4) {
			f, _ := os.ReadFile(m[2]) // #nosec G304 -- the planted flaw; the test server listens on loopback only
			doc = strings.ReplaceAll(doc, "&"+m[1]+";", string(f))
		}
		doc = reXMLDoctype.ReplaceAllString(doc, "")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, "<imported>"+doc+"</imported>")
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
	// The JSON API and its spec. An id below the documented minimum of 1
	// crashes the handler (500), as unchecked input would; other ids answer
	// as the spec says. Schemathesis's coverage phase always tries the
	// value below a minimum, so the crash is found on every run.
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, vulnAppSpec)
	})
	// The same spec in a Swagger UI page, as swagger-ui-express serves it
	// when mounted at /api-docs (ADR 0046).
	mux.HandleFunc("/api-docs/swagger-ui-init.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "\nwindow.onload = function() {\n  var options = {\n  \"swaggerDoc\": "+vulnAppSpec+",\n  \"customOptions\": {}\n};\n}\n")
	})
	mux.HandleFunc("/api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		switch {
		case err != nil:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"no such item"}`)
		case id < 1:
			http.Error(w, "internal server error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%d,"name":"hat"}`, id)
		}
	})
	// A login without a limit on failed attempts (CWE-307): every wrong
	// password gets the same answer, however many there are (ADR 0030).
	mux.HandleFunc("POST /account/sign-in", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"Invalid email or password."}`)
	})
	// A login that locks the account after 2 failed attempts: not an issue,
	// so the check must see the limit and report none.
	var failed sync.Map
	mux.HandleFunc("POST /account/sign-in-limited", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		n, _ := failed.LoadOrStore(r.Form.Get("username"), new(atomic.Int32))
		if n.(*atomic.Int32).Add(1) > 2 {
			http.Error(w, "account locked", http.StatusLocked)
			return
		}
		http.Error(w, "wrong password", http.StatusUnauthorized)
	})
	// A Tomcat manager page that still accepts the factory login
	// tomcat:tomcat (ADR 0031). The page has the words Nuclei's
	// tomcat-default-login template looks for.
	mux.HandleFunc("/manager/html", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "tomcat" || p != "tomcat" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		page(w, "<h1>Apache Tomcat Web Application Manager</h1><h2>Server Information</h2><table><tr><td>Tomcat Version</td><td>Apache Tomcat/9.0.0</td><td>JVM Version</td><td>11</td></tr></table>")
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
	// Orders (ADR 0035). /api/orders/{id} answers any logged-in account
	// (CWE-639): account B reads account A's order. /api/own-orders/{id}
	// checks the owner, and /api/my/orders answers each account its own
	// orders: neither is an issue. /account/profile answers with no login
	// at all (CWE-306).
	vulnAccounts := map[string]string{"Bearer token-a": "alice@shop.test", "Bearer token-b": "bob@shop.test", "Bearer token-c": "carol@shop.test"}
	mux.HandleFunc("GET /api/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		if vulnAccounts[r.Header.Get("Authorization")] == "" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"owner":"alice@shop.test","total":42}`, r.PathValue("id"))
	})
	mux.HandleFunc("GET /api/own-orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch vulnAccounts[r.Header.Get("Authorization")] {
		case "":
			http.Error(w, "log in first", http.StatusUnauthorized)
		case "alice@shop.test":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%q,"owner":"alice@shop.test","total":42}`, r.PathValue("id"))
		default:
			http.Error(w, "not your order", http.StatusForbidden)
		}
	})
	mux.HandleFunc("GET /api/my/orders", func(w http.ResponseWriter, r *http.Request) {
		who := vulnAccounts[r.Header.Get("Authorization")]
		if who == "" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":[{"owner":%q}]}`, who)
	})
	// A member list that gives anyone each member's password hash
	// (CWE-200, ADR 0035).
	mux.HandleFunc("GET /api/members", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"members":[{"name":"carol","passwordHash":"$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}]}`)
	})
	// Carts (ADR 0049). Each account reads and deletes only its own cart,
	// but any logged-in account can change a cart's quantity (CWE-639):
	// account B changes account A's cart. Nothing here is linked from a
	// page, so the crawling tools do not reach it.
	var cartMu sync.Mutex
	type cart struct {
		owner string
		qty   int
	}
	carts, nextCart := map[string]*cart{}, 1
	mux.HandleFunc("POST /api/carts/", func(w http.ResponseWriter, r *http.Request) {
		u := vulnAccounts[r.Header.Get("Authorization")]
		if u == "" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		cartMu.Lock()
		defer cartMu.Unlock()
		id := strconv.Itoa(nextCart)
		nextCart++
		carts[id] = &cart{owner: u, qty: 1}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","data":{"id":%s,"qty":1}}`, id)
	})
	cartOf := func(w http.ResponseWriter, r *http.Request, ownerOnly bool) *cart {
		u := vulnAccounts[r.Header.Get("Authorization")]
		c, ok := carts[r.PathValue("id")]
		switch {
		case u == "":
			http.Error(w, "log in first", http.StatusUnauthorized)
		case !ok || ownerOnly && c.owner != u:
			http.NotFound(w, r)
		default:
			return c
		}
		return nil
	}
	mux.HandleFunc("GET /api/carts/{id}", func(w http.ResponseWriter, r *http.Request) {
		cartMu.Lock()
		defer cartMu.Unlock()
		if c := cartOf(w, r, true); c != nil {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"data":{"qty":%d}}`, c.qty)
		}
	})
	mux.HandleFunc("PUT /api/carts/{id}", func(w http.ResponseWriter, r *http.Request) {
		cartMu.Lock()
		defer cartMu.Unlock()
		if c := cartOf(w, r, false); c != nil {
			c.qty++
			fmt.Fprint(w, `{"status":"success"}`)
		}
	})
	mux.HandleFunc("DELETE /api/carts/{id}", func(w http.ResponseWriter, r *http.Request) {
		cartMu.Lock()
		defer cartMu.Unlock()
		if c := cartOf(w, r, true); c != nil {
			delete(carts, r.PathValue("id"))
			fmt.Fprint(w, `{"status":"success"}`)
		}
	})
	// A team alice and bob share (ADR 0051), shaped like the private
	// groups measured on Rocket.Chat and Mattermost: members read it and
	// rename it, carol (outside it) gets 403. Its history of deleted
	// messages answers any logged-in account (CWE-639), the flaw
	// Rocket.Chat's chat.getDeletedMessages has: account C reads it.
	var teamMu sync.Mutex
	teamName := "secret-ab"
	teamMember := func(w http.ResponseWriter, r *http.Request) bool {
		switch vulnAccounts[r.Header.Get("Authorization")] {
		case "":
			http.Error(w, "log in first", http.StatusUnauthorized)
		case "alice@shop.test", "bob@shop.test":
			return true
		default:
			http.Error(w, "not a member", http.StatusForbidden)
		}
		return false
	}
	mux.HandleFunc("GET /api/teams/3", func(w http.ResponseWriter, r *http.Request) {
		teamMu.Lock()
		defer teamMu.Unlock()
		if teamMember(w, r) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":3,"name":%q,"members":["alice@shop.test","bob@shop.test"]}`, teamName)
		}
	})
	mux.HandleFunc("PUT /api/teams/3", func(w http.ResponseWriter, r *http.Request) {
		teamMu.Lock()
		defer teamMu.Unlock()
		if teamMember(w, r) {
			teamName += "!"
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success"}`)
		}
	})
	mux.HandleFunc("GET /api/teams/3/deleted", func(w http.ResponseWriter, r *http.Request) {
		if vulnAccounts[r.Header.Get("Authorization")] == "" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"deleted":[{"id":"m17","at":"2026-11-22T06:00:00Z"}]}`)
	})
	mux.HandleFunc("GET /account/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"alice@shop.test","address":"1 Main St"}`)
	})
	// A search with no rate limit (CWE-770, ADR 0036): every request gets
	// the same answer, however many there are.
	mux.HandleFunc("GET /api/suggest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"q":%q,"suggestions":[]}`, r.URL.Query().Get("q"))
	})
	// A report limited to 3 requests: not an issue, so the check must see
	// the limit (a 429 after the third) and report none.
	var reports atomic.Int32
	mux.HandleFunc("POST /api/report", func(w http.ResponseWriter, r *http.Request) {
		if reports.Add(1) > 3 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"rows":[]}`)
	})
	// A login limited for everyone after 3 failed attempts, whatever the
	// user name: login-throttle sees the limit, and spraying many user
	// names from the same address is limited too, so no finding
	// (ADR 0055). /account/sign-in-limited above locks only the account,
	// so spraying gets past it: a planted issue.
	var guarded atomic.Int32
	mux.HandleFunc("POST /account/sign-in-guarded", func(w http.ResponseWriter, r *http.Request) {
		if guarded.Add(1) > 3 {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "wrong password", http.StatusUnauthorized)
	})
	// Password resets with no limit (CWE-799, ADR 0055): every request
	// gets the same answer, however many there are; and resets limited to
	// 3 requests.
	mux.HandleFunc("POST /account/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "If the address has an account, we sent it an email.")
	})
	var resets atomic.Int32
	mux.HandleFunc("POST /account/forgot-password-limited", func(w http.ResponseWriter, r *http.Request) {
		if resets.Add(1) > 3 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, "If the address has an account, we sent it an email.")
	})
	// Sign-ups with no limit (CWE-799): each new user name makes an
	// account; a name taken already is refused.
	var accounts sync.Map
	mux.HandleFunc("POST /account/sign-up", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if _, taken := accounts.LoadOrStore(r.Form.Get("username"), true); taken || r.Form.Get("username") == "" {
			http.Error(w, "name taken", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	// Second-factor code pages, with express-rate-limit's headers (a
	// limit and the Unix time it resets): one with no limit at all
	// (CWE-307), one that allows 5 wrong codes a day (not an issue), and
	// one that allows 100 every 5 minutes like Juice Shop, 28,800 a day,
	// more than NIST's 100 (a planted low issue).
	code := func(limit string, window time.Duration) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if limit != "" {
				w.Header().Set("X-RateLimit-Limit", limit)
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(window).Unix(), 10))
			}
			http.Error(w, "wrong code", http.StatusUnauthorized)
		}
	}
	mux.HandleFunc("POST /account/2fa", code("", 0))
	mux.HandleFunc("POST /account/2fa-limited", code("5", 24*time.Hour))
	mux.HandleFunc("POST /account/2fa-loose", code("100", 5*time.Minute))
	return mux
}

// The planted keys of the served files, assembled at run time.
var (
	servedToken    = "gh" + "p_" + strings.Repeat("9zY8xW7vU6tS", 3)
	servedCloudKey = "AK" + "IA" + "QWERTYZXCV234567"
)

// vulnAppMinRequests is the least work a complete run of each container
// plugin does on the test app: requests through the egress proxy (ADR 0039).
// A run that sends fewer was cut short, whatever the reason, and fails.
// It is 90% of the fewest requests measured on 2026-11-20 in CI (podman
// 5.7.0 rootless and docker 29.4.2 rootful, both cgroup v2, run 44834908825)
// and locally (docker 29.10.0 rootful, cgroup v1).
var vulnAppMinRequests = map[string]int{
	"zap":                  7,     // 8 on all three
	"zap-active":           771,   // 857 on all three
	"nuclei":               10394, // 11,549 on all three
	"nuclei-intrusive":     900,   // 1,000 to 1,002
	"nuclei-default-login": 747,   // 831 on all three
	"ffuf":                 4282,  // 4,758 on all three
	"schemathesis":         18,    // 21 with vulnAppSchemathesisSeed on every run (12 local runs, 2026-11-21)
}

var (
	reXMLEntity  = regexp.MustCompile(`<!ENTITY\s+([A-Za-z_][\w.-]*)\s+SYSTEM\s+["']file://([^"']+)["']\s*>`)
	reXMLDoctype = regexp.MustCompile(`(?s)<\?xml[^>]*\?>|<!DOCTYPE[^\[>]*(\[.*?\])?\s*>`)
)

// vulnAppRecordedRequest is the recorded XML request given to zap-active, as a
// HAR file would hold it (ADR 0047).
const vulnAppRecordedRequest = `<?xml version="1.0"?><order><item>hat</item></order>`

// vulnAppSchemathesisSeed is the seed the test passes to Schemathesis, so
// that its count above is the same every run (see findsPlanted).
const vulnAppSchemathesisSeed = "1"

// vulnAppIssues maps each planted issue to the rule (ZAP rule ID or Nuclei
// template ID) that must report it, per plugin. A key "RULE /path" also
// needs the finding's location to end in /path (ffuf reports every guessed
// path under one rule).
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
		"90023": "XML external entity in POST /api/import, given as a recorded request",
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
	"nuclei-default-login": {
		"tomcat-default-login": "the Tomcat manager accepts the factory login tomcat:tomcat",
	},
	"ffuf": {
		"path-found /.env":        "exposed /.env",
		"path-found /.git/config": "exposed /.git/config",
	},
	"schemathesis": {
		"ST101 /api/items/{id}": "GET /api/items/{id} crashes (500) on an id below 1",
	},
	// SiegeKit's own checks: served-secrets runs Gitleaks
	// (TestServedFindsPlantedIssues), login-throttle runs in the test
	// process (TestLoginFindsPlantedIssue).
	"served-secrets": {
		"github-pat /static/app.js":           "a GitHub token in a served script",
		"aws-access-token /static/app.js.map": "an AWS access key in a served source map",
	},
	"login-throttle": {
		"login-not-limited /account/sign-in": "failed logins are not limited at POST /account/sign-in",
	},
	// public-maps runs in the test process (TestPublicMapsFindsPlantedIssues).
	"public-maps": {
		"public-api-spec /openapi.json":                "the API spec is served at /openapi.json",
		"public-api-spec /api-docs/swagger-ui-init.js": "the API spec is served in a Swagger UI page at /api-docs/",
		"public-source-map /static/app.js.map":         "the source map that app.js names is served",
		"public-source-map /static/vendor.js.map":      "a source map that vendor.js does not name is served",
	},
	// The page checks and spraying run in the test process
	// (TestPagesFindPlantedIssues, ADR 0055).
	"reset-limit": {
		"reset-not-limited /account/forgot-password": "password resets are not limited at POST /account/forgot-password",
	},
	"signup-limit": {
		"signup-not-limited /account/sign-up": "sign-ups are not limited at POST /account/sign-up",
	},
	"code-limit": {
		"code-not-limited /account/2fa":      "wrong second-factor codes are not limited at POST /account/2fa",
		"code-limit-high /account/2fa-loose": "POST /account/2fa-loose allows 100 wrong codes every 5 minutes, 28,800 a day",
	},
	"login-spray": {
		"spray-not-limited /account/sign-in-limited": "POST /account/sign-in-limited locks one account but not one password tried on many",
	},
	// rate-limit runs in the test process (TestRateLimitFindsPlantedIssue).
	"rate-limit": {
		"rate-not-limited /api/suggest": "requests to GET /api/suggest are not limited",
	},
	// access-control runs in the test process (TestAuthzFindsPlantedIssues).
	"access-control": {
		"cross-account-read /api/orders/7": "account B reads account A's order at GET /api/orders/7",
		"no-login-read /account/profile":   "account A's profile answers with no login",
		"no-login-secret /api/members":     "the member list gives anyone password hashes",
	},
	// access-control-write runs in the test process
	// (TestAuthzWriteFindsPlantedIssue).
	"access-control-write": {
		"cross-account-write /api/carts/1": "account B changes account A's cart at PUT /api/carts/1",
	},
}

// vulnAppOutsiderIssues are what the access-control checks must report
// when accounts B and C are both given (ADR 0051): bob shares team 3 with
// alice, carol is outside it (TestAuthzOutsiderFindsPlantedIssues).
var vulnAppOutsiderIssues = map[string]map[string]string{
	"access-control": {
		"cross-account-read /api/orders/7":        "account C reads account A's order at GET /api/orders/7",
		"cross-account-read /api/teams/3/deleted": "account C, outside the team, reads its deleted messages at GET /api/teams/3/deleted",
		"b-only-read /api/teams/3":                "account B, a member, reads the team A shares with it (low: allowed by design)",
		"no-login-read /account/profile":          "account A's profile answers with no login",
		"no-login-secret /api/members":            "the member list gives anyone password hashes",
	},
	"access-control-write": {
		"cross-account-write /api/carts/1": "account C changes account A's cart at PUT /api/carts/1",
		"b-only-write /api/teams/3":        "account B, a member, renames the team A shares with it (low: allowed by design)",
	},
}
