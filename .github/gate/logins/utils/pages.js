// The reset and sign-up pages of the page-form gate (ADR 0069): each run
// of a page's action counts toward its limit, and each run under the limit
// sends one email to Mailpit, so the gate counts the runs there. A run past
// the limit sends none. The counts live in the server process; the gate
// clears them before each scan (POST /gate-reset).
const counts = (globalThis.__gatePageCounts ??= {})

export async function run(page, to, limit) {
  counts[page] = (counts[page] || 0) + 1
  if (limit > 0 && counts[page] > limit) return false
  const res = await fetch(process.env.MAILPIT_URL + 'api/v1/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ From: { Email: 'gate@siegekit.test' }, To: [{ Email: String(to) }], Subject: page, Text: page }),
  })
  if (!res.ok) throw new Error('Mailpit answered ' + res.status)
  return true
}

export function clear() {
  for (const k of Object.keys(counts)) delete counts[k]
}
