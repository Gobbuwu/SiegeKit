'use server'
import { redirect } from 'next/navigation'
import { run } from '../../utils/pages'
// A sign-up limited to 10, shown only in the redirect (as Porchlet shows
// Supabase's limits).
export async function signup(formData) {
  if (!(await run('signup', formData.get('email'), 10))) redirect('/signup?error=too-many-attempts')
  redirect('/signup?notice=check-email')
}
