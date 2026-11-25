'use server'
import { run } from '../../utils/pages'
// A sign-up with no limit that answers 200 with the form's state, as a
// useActionState form does.
export async function signup(prev, formData) {
  await run('signup2', formData.get('email'), 0)
  return { notice: 'Check your email.' }
}
