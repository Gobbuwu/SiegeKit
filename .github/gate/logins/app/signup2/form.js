'use client'
import { useActionState } from 'react'
import { signup } from './actions'
export default function Form() {
  const [state, action, pending] = useActionState(signup, null)
  return (<form action={action}>
    <input name="email" type="email" required /><input name="password" type="password" required />
    <button disabled={pending}>Sign up</button>{state?.notice && <p role="status">{state.notice}</p>}
  </form>)
}
