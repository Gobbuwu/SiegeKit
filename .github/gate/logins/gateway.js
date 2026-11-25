// The form login gate's stand-in for the hosted Supabase gateway (ADR 0062):
// it serves Supabase Auth under /auth/v1 and sets X-Forwarded-For to the
// TCP peer, replacing any the client sent, as the hosted gateway sets the
// client address. Supabase Auth limits logins by that address.
const http = require('http');
http.createServer((req, res) => {
  if (!req.url.startsWith('/auth/v1/')) { res.writeHead(404); return res.end(); }
  const h = { ...req.headers, 'x-forwarded-for': req.socket.remoteAddress.replace('::ffff:', '') };
  delete h.host;
  const up = http.request({ host: '127.0.0.1', port: 9999, path: req.url.slice(8), method: req.method, headers: h }, u => {
    res.writeHead(u.statusCode, u.headers); u.pipe(res);
  });
  up.on('error', () => { res.writeHead(502); res.end(); });
  req.pipe(up);
  console.log(new Date().toISOString(), h['x-forwarded-for'], req.method, req.url);
}).listen(54331, '127.0.0.1');
