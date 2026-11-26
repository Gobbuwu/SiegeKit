'use server'
// Server Actions of the write-replay gate (issues #95 and #96), each
// posted to the page's own URL with a Next-Action header. Owner-only
// actions answer a refusal with the form's state (status 200, no
// redirect), as Porchlet's do. Three are flawed on purpose: addNote and
// setWebhook let any signed-in account write to any workspace, and
// sendFeedback needs no login.
import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { byId, create, currentUser, isOwner } from '../../utils/workspaces'

const page = (id) => '/w/' + id
async function owned(formData) {
  const u = await currentUser()
  if (!u) redirect('/login?next=/w')
  const w = byId(String(formData.get('workspace_id') || ''))
  return isOwner(w, u) ? w : null
}

export async function createWorkspace(_s, formData) {
  const u = await currentUser()
  if (!u) redirect('/login?next=/w')
  const name = String(formData.get('name') || '').trim()
  if (!name) return { error: 'name-required' }
  redirect(page(create(u, name).id) + '?notice=created')
}
// Success redirects (x-action-redirect), as Porchlet's actions do.
export async function rename(_s, formData) {
  const w = await owned(formData)
  if (!w) return { error: 'not-allowed' }
  w.name = String(formData.get('name') || '').trim() || w.name
  redirect(page(w.id) + '?notice=renamed')
}
export async function addMember(_s, formData) {
  const w = await owned(formData)
  if (!w) return { error: 'not-allowed' }
  const email = String(formData.get('email') || '').trim()
  if (email && !w.members.includes(email)) w.members.push(email)
  redirect(page(w.id) + '?notice=member-added')
}
// Success revalidates the page and answers the form (x-action-revalidated,
// no redirect).
export async function archive(_s, formData) {
  const w = await owned(formData)
  if (!w) return { error: 'not-allowed' }
  w.archived = !w.archived
  revalidatePath(page(w.id))
  return { notice: w.archived ? 'archived' : 'restored' }
}
// Success only answers the form: no redirect, no revalidation, so its
// answer looks like a refusal's.
export async function setTopic(_s, formData) {
  const w = await owned(formData)
  if (!w) return { error: 'not-allowed' }
  w.topic = String(formData.get('topic') || '')
  return { notice: 'saved' }
}
// Flawed: any signed-in account adds a note to any workspace.
export async function addNote(_s, formData) {
  const u = await currentUser()
  if (!u) redirect('/login?next=/w')
  const w = byId(String(formData.get('workspace_id') || ''))
  if (!w) return { error: 'not-found' }
  w.notes.push(String(formData.get('note') || ''))
  redirect(page(w.id) + '?notice=note-added')
}
// Flawed: any signed-in account sets any workspace's webhook, which no
// page shows.
export async function setWebhook(_s, formData) {
  const u = await currentUser()
  if (!u) redirect('/login?next=/w')
  const w = byId(String(formData.get('workspace_id') || ''))
  if (!w) return { error: 'not-found' }
  w.webhook = String(formData.get('url') || '')
  redirect(page(w.id) + '?notice=webhook-saved')
}
// Flawed: no login needed.
export async function sendFeedback(_s, formData) {
  const w = byId(String(formData.get('workspace_id') || ''))
  if (!w) return { error: 'not-found' }
  w.feedback++
  redirect('/p/' + w.id + '?notice=thanks')
}
