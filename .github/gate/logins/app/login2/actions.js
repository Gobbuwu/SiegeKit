'use server'
import { redirect } from 'next/navigation'
import { createClient } from '../../utils/server'
export async function login(prev, formData) {
  const supabase = await createClient()
  const { error } = await supabase.auth.signInWithPassword({ email: formData.get('email'), password: formData.get('password') })
  if (error) return { error: error.message }
  redirect('/')
}
