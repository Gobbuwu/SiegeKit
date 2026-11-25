import { forgot } from './actions'
export default function ForgotPage() {
  return (<form>
    <label htmlFor="email">Email:</label><input id="email" name="email" type="email" required />
    <button formAction={forgot}>Send reset link</button>
  </form>)
}
