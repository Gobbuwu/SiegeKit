'use client'
import { useActionState } from 'react'
import { login } from './actions'
export default function Form() {
  const [state, action, pending] = useActionState(login, null)
  return (<form action={action}>
    <input name="email" type="email" required /><input name="password" type="password" required />
    <button disabled={pending}>Log in</button>{state?.error && <p role="alert">{state.error}</p>}
  </form>)
}
