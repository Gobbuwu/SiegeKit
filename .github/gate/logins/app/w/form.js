'use client'
import { useActionState } from 'react'
// One form per action, answered with its state (useActionState), as
// Porchlet's forms are.
export default function ActionForm({ action, id, name, label, fields = [] }) {
  const [state, run, pending] = useActionState(action, null)
  return (<form action={run} id={name}>
    <input type="hidden" name="workspace_id" value={id || ''} />
    {fields.map((f) => <input key={f} name={f} aria-label={f} />)}
    <button disabled={pending}>{label}</button>
    {state?.error && <p role="alert">{state.error}</p>}{state?.notice && <p role="status">{state.notice}</p>}
  </form>)
}
