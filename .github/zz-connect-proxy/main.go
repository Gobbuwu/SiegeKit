// Minimal HTTP CONNECT proxy for a measurement: forwards CONNECT host:443 and logs each target.
package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	log.Fatal(http.ListenAndServe(os.Args[1], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		log.Printf("CONNECT %s", r.Host)
		up, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		go func() { io.Copy(up, c); up.Close() }()
		io.Copy(c, up)
		c.Close()
	})))
}
