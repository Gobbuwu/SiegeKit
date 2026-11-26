'use server'
import { redirect } from 'next/navigation'
import { run } from '../../../utils/pages'
// An invite, limited to 20 (Porchlet's invite cap); each run under the
// limit emails Mailpit, so the gate sees whether a scan reached it.
export async function invite(formData) {
  if (!(await run('invite', formData.get('email'), 20))) redirect('/w/' + encodeURIComponent(formData.get('workspace_id')) + '?error=too-many-invites')
  redirect('/w/' + encodeURIComponent(formData.get('workspace_id')) + '?notice=invited')
}
