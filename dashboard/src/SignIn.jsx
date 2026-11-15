import { useState } from 'react'
import { api } from './api'
import { ROLE_LABELS, authMode, login, logout, setDevSession, takeAuthError } from './auth'
import { Badge } from './ui'

// Shown instead of any page while nobody is signed in. Every data route requires a role.
export function SignInPanel() {
  const oidc = authMode() === 'oidc'
  const [authError] = useState(() => takeAuthError())
  const [subject, setSubject] = useState('alice')
  const [role, setRole] = useState('SECURITY_REVIEWER')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function devSignIn() {
    setBusy(true)
    setError(null)
    try {
      const { token } = await api.getDevToken(subject, role)
      setDevSession(token)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card" data-testid="sign-in-panel">
      <h3>Sign in to continue</h3>
      {(authError || error) && <div role="alert" data-testid="auth-error">{authError || error}</div>}
      {oidc ? (
        <>
          <p className="sub">
            Everything here is limited by your role. You will be sent to the identity provider and brought back.
          </p>
          <button onClick={login} data-testid="sign-in">Sign in</button>
        </>
      ) : (
        <>
          <p className="sub">
            Demo sign-in for local development only (the API issues a token for any role you pick). Roles decide
            which pages you can open; try more than one.
          </p>
          <div className="form-row">
            <label className="field">
              Name
              <input value={subject} onChange={(e) => setSubject(e.target.value)} data-testid="subject-input" />
            </label>
            <label className="field">
              Role
              <select value={role} onChange={(e) => setRole(e.target.value)} data-testid="role-select">
                {Object.entries(ROLE_LABELS).map(([key, label]) => (
                  <option key={key} value={key}>{label}</option>
                ))}
              </select>
            </label>
            <button onClick={devSignIn} disabled={busy} data-testid="dev-sign-in">
              {busy ? 'Signing in...' : 'Sign in'}
            </button>
          </div>
        </>
      )}
    </section>
  )
}

export function SessionChip({ session }) {
  const roles = (session.claims.realm_access?.roles || []).filter((r) => r in ROLE_LABELS)
  return (
    <div className="session-chip" data-testid="session-chip">
      <span>
        Signed in as <b data-testid="signed-in-user">{session.claims.preferred_username || session.claims.sub}</b>
      </span>
      {roles.map((r) => <Badge key={r} tone="info">{ROLE_LABELS[r]}</Badge>)}
      <button className="ghost" onClick={logout} data-testid="sign-out">Sign out</button>
    </div>
  )
}
