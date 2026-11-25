'use server'
import { redirect } from 'next/navigation'
import { run } from '../../utils/pages'
// A password reset limited to 5, shown only in the redirect.
export async function forgot(formData) {
  if (!(await run('forgot', formData.get('email'), 5))) redirect('/forgot?error=too-many-attempts')
  redirect('/forgot?notice=check-email')
}
