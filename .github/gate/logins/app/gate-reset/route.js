import { clear } from '../../utils/pages'
// Clears the page counts between the gate's scans.
export async function POST() {
  clear()
  return new Response('cleared\n')
}
