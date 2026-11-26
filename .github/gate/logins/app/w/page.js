import Link from 'next/link'
import { redirect } from 'next/navigation'
import { currentUser, mine } from '../../utils/workspaces'
import ActionForm from './form'
import { createWorkspace } from './actions'
export default async function Workspaces() {
  const u = await currentUser()
  if (!u) redirect('/login?next=/w')
  return (<main><h1>Workspaces of {u.email}</h1>
    <ul>{mine(u).map((w) => <li key={w.id}><Link href={'/w/' + w.id}>{w.name}</Link></li>)}</ul>
    <ActionForm action={createWorkspace} name="create" label="Create" fields={['name']} />
    <Link href="/latest" prefetch={true}>Newest workspace</Link>
  </main>)
}
