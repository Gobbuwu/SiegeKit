// MEASUREMENT PROTOTYPE, NOT FOR MERGE (#86, #87).
// blocksrv: a stand-in for a Vercel-hosted Next.js app whose host starts
// answering every request with one 403 block page after N requests
// (or while the file BLOCKFILE exists).
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "")
	after := flag.Int64("after", -1, "block from request N (1-based); -1 never")
	blockFile := flag.String("blockfile", "", "block while this file exists")
	until := flag.Int64("until", -1, "stop blocking from request M; -1 never")
	upstream := flag.String("upstream", "", "proxy unblocked requests to this app")
	reqHdr := flag.String("require-header", "", "NAME=VALUE: without it, redirect to an SSO page (Vercel Authentication stand-in)")
	flag.Parse()
	var rp *httputil.ReverseProxy
	if *upstream != "" {
		u, err := url.Parse(*upstream)
		if err != nil {
			log.Fatal(err)
		}
		rp = httputil.NewSingleHostReverseProxy(u)
	}
	hName, hVal, _ := strings.Cut(*reqHdr, "=")
	var n atomic.Int64
	pad := strings.Repeat("<!-- vercel security checkpoint -->\n", 680)
	block := `<!doctype html><html><head><meta name="generator" content="Astro v4.16.0"><title>Vercel Security Checkpoint</title></head><body><h1>403</h1><p>We're verifying your browser.</p>` + pad + `</body></html>`
	notFound := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>404: This page could not be found.</title><script src="/_next/static/chunks/main.js"></script></head><body><div id="__next"><h1>404</h1><h2>This page could not be found.</h2></div></body></html>`
	home := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Porch</title><script src="/_next/static/chunks/main.js"></script></head><body><div id="__next"><a href="/about">About</a> <a href="/login">Log in</a></div></body></html>`
	appHdr := func(w http.ResponseWriter) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=()")
		h.Set("X-Powered-By", "Next.js")
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		blocked := (*after > 0 && i >= *after) && (*until < 0 || i < *until)
		if *blockFile != "" {
			if _, err := os.Stat(*blockFile); err == nil {
				blocked = true
			}
		}
		ua := r.UserAgent()
		if len(ua) > 40 {
			ua = ua[:40]
		}
		code := 0
		hdr := "-"
		if hName != "" {
			hdr = "no"
			if r.Header.Get(hName) == hVal {
				hdr = "yes"
			}
		}
		rh := "no" // a refused header (Cookie or Authorization from the H1 list) reached the app
		if strings.Contains(r.Header.Get("Cookie"), "refused=1") || r.Header.Get("Authorization") == "Bearer refused" {
			rh = "yes"
		}
		defer func() { log.Printf("%d %s %s %d hdr=%s ua=%q rh=%s", i, r.Method, r.URL.RequestURI(), code, hdr, ua, rh) }()
		if hdr == "no" {
			code = 302
			w.Header().Set("Location", "https://vercel.com/sso-api?url="+url.QueryEscape(r.URL.RequestURI()))
			w.WriteHeader(302)
			return
		}
		if blocked {
			code = 403
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Server", "Vercel")
			w.WriteHeader(403)
			fmt.Fprint(w, block)
			return
		}
		if rp != nil {
			code = -1 // upstream
			rp.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/", "/about", "/login":
			code = 200
			appHdr(w)
			fmt.Fprint(w, home)
		case "/_next/static/chunks/main.js":
			code = 200
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("app")`)
		case "/robots.txt":
			code = 200
			fmt.Fprint(w, "User-agent: *\nAllow: /\n")
		default:
			code = 404
			appHdr(w)
			w.WriteHeader(404)
			fmt.Fprint(w, notFound)
		}
	})
	log.SetFlags(log.Lmicroseconds)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
