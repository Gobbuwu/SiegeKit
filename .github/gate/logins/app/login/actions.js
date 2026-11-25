'use server'
import { redirect } from 'next/navigation'
import { createClient } from '../../utils/server'
export async function login(formData) {
  const supabase = await createClient()
  const { error } = await supabase.auth.signInWithPassword({ email: formData.get('email'), password: formData.get('password') })
  if (error) redirect('/error?code=' + encodeURIComponent(error.code || error.status))
  redirect('/')
}
