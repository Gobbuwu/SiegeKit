import { invite } from './actions'
// A workspace's invite page, reached only with a session (proxy.js).
export default async function WorkspacePage({ params }) {
  const { id } = await params
  return (<form>
    <input type="hidden" name="workspace_id" value={id} />
    <label htmlFor="email">Email:</label><input id="email" name="email" type="email" required />
    <button formAction={invite}>Invite</button>
  </form>)
}
