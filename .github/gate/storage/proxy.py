# /storage/v1/* -> 127.0.0.1:5000/* (the gateway layout of a real project)
# Plain HTTP to the fixed loopback upstream, sent as received: like a real
# gateway, it adds no headers and follows no redirects.
import http.client, http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def go(self):
        if not self.path.startswith('/storage/v1/'):
            self.send_response(404); self.end_headers(); return
        n=int(self.headers.get('Content-Length') or 0); body=self.rfile.read(n) if n else None
        c=http.client.HTTPConnection('127.0.0.1', int(sys.argv[2]))
        c.request(self.command, self.path[len('/storage/v1'):], body=body,
                  headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','content-length','connection')})
        r=c.getresponse(); data=r.read(); c.close()
        self.send_response(r.status)
        for k,v in r.getheaders():
            if k.lower() not in ('transfer-encoding','connection','content-length'): self.send_header(k,v)
        self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET=do_POST=do_DELETE=do_PUT=do_HEAD=go
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
