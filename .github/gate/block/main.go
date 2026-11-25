// Command block is the gate's stand-in for a host that stops serving the
// app partway through a scan (ADR 0071, issue #86), as Vercel's Security
// Checkpoint did on Porchlet's R1p run: from the Nth request whose
// User-Agent matches -ua, every request gets one 403 page of about 25 KB
// whose length differs by up to 10 bytes per answer (the real page was
// 25,124 and 25,134 bytes in two fetches) and whose markup names Astro, as
// the real page's does. Other requests are passed to the app.
//
// SiegeKit's start-page fetches (User-Agent ending in "(start page
// check)") are never counted; with -lift-after-pages K the block ends at
// the Kth of them made while it was on, so the next check finds the app
// again.
//
// With -gzip the host compresses every answer whose request accepts gzip
// and that the app did not compress itself, as hosts such as Vercel do.
//
// Every request is logged as one line, once answered: "<n> page=yes|no
// blocked=yes|no <method> <path> bytes=<b>", n counting the matching
// requests and b the bytes of the answer's body as sent.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	app := flag.String("app", "http://127.0.0.1:3001", "the app")
	ua := flag.String("ua", ".", "count requests whose User-Agent matches this")
	after := flag.Int("after", 0, "block from the Nth counted request; 0 never")
	lift := flag.Int("lift-after-pages", 0, "end the block at the Kth start-page fetch made during it; 0 never")
	logFile := flag.String("log", "", "request log")
	gz := flag.Bool("gzip", false, "compress answers for requests that accept gzip")
	flag.Parse()
	re := regexp.MustCompile(*ua)
	u, err := url.Parse(*app)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the log the gate names
	if err != nil {
		log.Fatal(err)
	}
	pad := strings.Repeat("<!-- checkpoint -->\n", 1240)
	var (
		mu      sync.Mutex
		n       int
		on      bool
		pages   int
		answers int
	)
	rp := httputil.NewSingleHostReverseProxy(u)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := strings.HasSuffix(r.UserAgent(), "(start page check)")
		mu.Lock()
		if !page && re.MatchString(r.UserAgent()) {
			n++
			if *after > 0 && n == *after {
				on = true
			}
		}
		blocked := on
		if on && page {
			pages++
			if *lift > 0 && pages == *lift {
				on = false
			}
		}
		if blocked {
			answers++
		}
		i, extra := n, answers%11
		mu.Unlock()
		cw := &countWriter{ResponseWriter: w}
		var out http.ResponseWriter = cw
		var z *gzipWriter
		if *gz && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			z = &gzipWriter{ResponseWriter: cw}
			out = z
		}
		if !blocked {
			rp.ServeHTTP(out, r)
		} else {
			out.Header().Set("Content-Type", "text/html; charset=utf-8")
			out.Header().Set("Server", "Vercel")
			out.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(out, `<!doctype html><html><head><meta name="generator" content="Astro v4.16.0"><title>Security Checkpoint</title></head><body><h1>403</h1><p>We're verifying your browser.%s</p>%s</body></html>`, strings.Repeat(".", extra), pad)
		}
		if z != nil {
			z.close()
		}
		mu.Lock()
		fmt.Fprintf(f, "%d page=%s blocked=%s %s %q bytes=%d\n", i, yes(page), yes(blocked), r.Method, r.URL.Path, cw.n)
		mu.Unlock()
	})
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 30 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// countWriter counts the body bytes sent.
type countWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

// gzipWriter compresses an answer the app did not compress itself.
type gzipWriter struct {
	http.ResponseWriter
	z       *gzip.Writer
	decided bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.decided {
		g.decided = true
		h := g.Header()
		if h.Get("Content-Encoding") == "" && code != http.StatusNoContent && code != http.StatusNotModified {
			h.Set("Content-Encoding", "gzip")
			h.Del("Content-Length")
			g.z = gzip.NewWriter(g.ResponseWriter)
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		g.WriteHeader(http.StatusOK)
	}
	if g.z != nil {
		return g.z.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipWriter) close() {
	if g.z != nil {
		g.z.Close() // #nosec G104 -- the answer is already sent; a failed close only truncates it
	}
}
