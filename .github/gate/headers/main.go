// Command headers is the gate's stand-in for a hosting provider's login in
// front of a preview (ADR 0070): a request without the bypass header gets
// a 302 to a login page, as Vercel Authentication answers, and one with it
// is passed to the app without the header. Every request is logged as one
// line, "<method> <path> header=yes|no", so the gate can count the
// requests that reached the app without it.
//
// The secret is read from the environment, never from a flag, so it is not
// in the process list.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	app := flag.String("app", "http://127.0.0.1:3001", "the app behind the login")
	name := flag.String("header", "X-Vercel-Protection-Bypass", "the bypass header")
	logFile := flag.String("log", "", "request log")
	flag.Parse()
	secret := os.Getenv("GATE_BYPASS_SECRET")
	if len(secret) < 8 {
		log.Fatal("GATE_BYPASS_SECRET must hold the secret")
	}
	u, err := url.Parse(*app)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the log the gate names
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	rp := httputil.NewSingleHostReverseProxy(u)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := r.Header.Get(*name) == secret && len(r.Header.Values(*name)) == 1
		mu.Lock()
		fmt.Fprintf(f, "%s %q header=%s\n", r.Method, r.URL.Path, map[bool]string{true: "yes", false: "no"}[ok])
		mu.Unlock()
		if !ok {
			http.Redirect(w, r, "https://vercel.example/sso-api?url="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		r.Header.Del(*name)
		rp.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 30 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
