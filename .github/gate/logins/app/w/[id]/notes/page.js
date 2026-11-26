import { redirect } from 'next/navigation'
import { byId, currentUser } from '../../../../utils/workspaces'
// Flawed: any signed-in account reads any workspace's notes.
export default async function Notes({ params }) {
  const { id } = await params
  if (!(await currentUser())) redirect('/login?next=/w/' + id + '/notes')
  const w = byId(id)
  return <main><h1>Notes</h1><ul>{(w?.notes || []).map((n, i) => <li key={i}>{n}</li>)}</ul></main>
}
