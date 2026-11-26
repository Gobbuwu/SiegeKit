import ActionForm from '../../w/form'
import { sendFeedback } from '../../w/actions'
import { byId } from '../../../utils/workspaces'
// A workspace's public page: feedback needs no login.
export const dynamic = 'force-dynamic'
export default async function Public({ params }) {
  const { id } = await params
  const w = byId(id)
  return <main><h1>Feedback</h1><p>Received: {w ? w.feedback : 0}</p><ActionForm action={sendFeedback} id={id} name="feedback" label="Send feedback" /></main>
}
