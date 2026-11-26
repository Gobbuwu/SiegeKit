import Link from 'next/link'
import { redirect } from 'next/navigation'
import { byId, canSee, currentUser, isOwner } from '../../../utils/workspaces'
import ActionForm from '../form'
import { addMember, addNote, archive, rename, setTopic, setWebhook } from '../actions'
export default async function Workspace({ params }) {
  const { id } = await params
  const u = await currentUser()
  if (!u) redirect('/login?next=/w/' + id)
  const w = byId(id)
  if (!canSee(w, u)) return <main><h1>No access</h1><p>This workspace does not exist or is not shared with you.</p><Link href="/w">Workspaces</Link></main>
  const owner = isOwner(w, u)
  return (<main><h1>{w.name}</h1>
    <p>Topic: {w.topic || 'none'}</p><p>{w.archived ? 'Archived' : 'Active'}</p>
    <p>Members: {w.members.join(', ') || 'none'}</p><p>Notes: {w.notes.length}</p><p>Feedback: {w.feedback}</p>
    <Link href={'/w/' + id + '/notes'}>Notes</Link> <Link href={'/p/' + id}>Public page</Link> <Link href="/w">Workspaces</Link>
    {owner && <>
      <ActionForm action={rename} id={id} name="rename" label="Rename" fields={['name']} />
      <ActionForm action={archive} id={id} name="archive" label={w.archived ? 'Restore' : 'Archive'} />
      <ActionForm action={setTopic} id={id} name="topic" label="Set topic" fields={['topic']} />
      <ActionForm action={addMember} id={id} name="member" label="Add member" fields={['email']} />
    </>}
    <ActionForm action={addNote} id={id} name="note" label="Add note" fields={['note']} />
    <ActionForm action={setWebhook} id={id} name="webhook" label="Set webhook" fields={['url']} />
  </main>)
}
