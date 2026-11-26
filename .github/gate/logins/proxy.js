import { NextResponse } from 'next/server'
// Issue #94 (ADR 0073): workspace pages behind a login wall, as Porchlet's
// proxy sends a request with no session to /login?next=... with a 307
// before any page or Server Action runs. A session here is any Supabase
// auth cookie; the gate's scans of /w send none.
export function proxy(request) {
  if (request.cookies.getAll().some((c) => /^sb-.*-auth-token/.test(c.name))) return NextResponse.next()
  const login = new URL('/login', request.url)
  login.searchParams.set('next', request.nextUrl.pathname + request.nextUrl.search)
  return NextResponse.redirect(login)
}

export const config = { matcher: '/w/:path*' }
