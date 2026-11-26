import { redirect } from 'next/navigation'
import { currentUser, newest } from '../../utils/workspaces'
// Flawed: every signed-in account reads the newest workspace's name, an
// answer whose URL holds no ID and that does not name its owner.
export default async function Latest() {
  if (!(await currentUser())) redirect('/login?next=/latest')
  const w = newest()
  return <main><h1>Newest workspace</h1><p>{w ? w.name : 'none'}</p></main>
}
