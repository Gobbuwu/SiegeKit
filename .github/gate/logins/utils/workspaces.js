// The workspace pages of the write-replay gate (issues #95 and #96): a
// Porchlet-like Next.js app whose writes are Server Actions posted to the
// page's own URL. The data lives in the server process.
import { createClient } from './server'

const store = (globalThis.__gateWorkspaces ??= { list: [] })

export async function currentUser() {
  const supabase = await createClient()
  const { data } = await supabase.auth.getUser()
  return data?.user ? { id: data.user.id, email: data.user.email } : null
}

export function create(owner, name) {
  const w = { id: crypto.randomUUID(), name, owner: owner.id, members: [], topic: '', archived: false, notes: [], webhook: '', feedback: 0 }
  store.list.push(w)
  return w
}
export const byId = (id) => store.list.find((w) => w.id === id)
export const isOwner = (w, u) => !!w && !!u && w.owner === u.id
export const canSee = (w, u) => isOwner(w, u) || (!!w && !!u && w.members.includes(u.email))
export const mine = (u) => store.list.filter((w) => canSee(w, u))
export const newest = () => store.list[store.list.length - 1]
