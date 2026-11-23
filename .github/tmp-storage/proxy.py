# /storage/v1/* -> 127.0.0.1:5000/* (the gateway layout of a real project)
import http.server, urllib.request, sys
class H(http.server.BaseHTTPRequestHandler):
    def go(self):
        if not self.path.startswith('/storage/v1/'):
            self.send_response(404); self.end_headers(); return
        n=int(self.headers.get('Content-Length') or 0); body=self.rfile.read(n) if n else None
        req=urllib.request.Request('http://127.0.0.1:'+sys.argv[2]+self.path[len('/storage/v1'):], data=body, method=self.command)
        for k,v in self.headers.items():
            if k.lower() not in ('host','content-length','connection'): req.add_header(k,v)
        try: r=urllib.request.urlopen(req)
        except urllib.error.HTTPError as e: r=e
        data=r.read(); self.send_response(r.status if hasattr(r,'status') else r.code)
        for k,v in r.headers.items():
            if k.lower() not in ('transfer-encoding','connection','content-length'): self.send_header(k,v)
        self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET=do_POST=do_DELETE=do_PUT=do_HEAD=go
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
