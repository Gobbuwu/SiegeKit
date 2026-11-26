import { newest } from '../../utils/workspaces'
// Flawed: every workspace page's layout names the newest workspace, of any
// account. A prefetch of a page under it can carry this layout (issue #96).
export const dynamic = 'force-dynamic'
export default function Layout({ children }) {
  const w = newest()
  return <>{w && <aside>Newest: {w.name}</aside>}{children}</>
}
