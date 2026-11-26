import { NextResponse } from 'next/server'
// The write-replay gate's pages (issues #95 and #96) as Porchlet serves
// them: a Content-Security-Policy with a fresh nonce on every answer, and
// a visitor with no session cookie sent to the login page. Only these
// pages: the login gate's pages answer as they did (ADR 0062).
export function proxy(request) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
  const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'nonce-${nonce}'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`
  const path = request.nextUrl.pathname
  let response
  if ((path === '/w' || path.startsWith('/w/') || path === '/latest') && !request.cookies.getAll().some((c) => c.name.startsWith('sb-'))) {
    const login = new URL('/login', request.url)
    login.searchParams.set('next', path + request.nextUrl.search)
    response = NextResponse.redirect(login)
  } else {
    const h = new Headers(request.headers)
    h.set('x-nonce', nonce)
    h.set('content-security-policy', csp)
    response = NextResponse.next({ request: { headers: h } })
  }
  response.headers.set('content-security-policy', csp)
  return response
}
export const config = { matcher: ['/w', '/w/:path*', '/p/:path*', '/latest'] }
