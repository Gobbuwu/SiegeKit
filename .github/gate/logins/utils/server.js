import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
// Supabase's own Next.js server-side auth guide pattern; URL and key read on the server only.
export async function createClient() {
  const cookieStore = await cookies()
  return createServerClient(process.env.SUPABASE_URL, process.env.SUPABASE_PUBLISHABLE_KEY, {
    cookies: {
      getAll() { return cookieStore.getAll() },
      setAll(cs) { try { cs.forEach(({ name, value, options }) => cookieStore.set(name, value, options)) } catch {} },
    },
  })
}
