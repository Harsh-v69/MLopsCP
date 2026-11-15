import { useEffect, useState } from 'react'
import { api } from '../api'
import { authMode, currentSession, login, logout, signOutLocal, takeAuthError } from '../auth'
import { Badge, PageHead } from '../ui'

// Dev-only "sign in": no real identity provider in this MVP (see
// docs/phase9_transparency_spec.md Part C and docs/phase8_governance_spec.md).
// A role with no view_audit_log permission gets a real 403, not a hidden tab.
const ROLES = {
  DATA_ENGINEER: { label: 'Data Engineer', canView: false },
  ML_ENGINEER: { label: 'ML Engineer', canView: false },
  SECURITY_REVIEWER: { label: 'Security Reviewer', canView: true },
  APPROVER: { label: 'Approver', canView: true },
}

function actionTone(action) {
  if (/approved|passed|verified/.test(action)) return 'pass'
  if (/rejected|blocked|denied|failed|quarantined/.test(action)) return 'fail'
  if (/borderline|pending/.test(action)) return 'warn'
  return 'info'
}

function formatTime(iso) {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export default function AuditTrail() {
  const [subject, setSubject] = useState('alice')
  const [role, setRole] = useState('SECURITY_REVIEWER')
  const [state, setState] = useState({ status: 'idle', data: null, error: null })

  const oidc = authMode() === 'oidc'
  const session = oidc ? currentSession() : null
  const [authError] = useState(() => (oidc ? takeAuthError() : null))

  async function fetchLog(token) {
    setState({ status: 'loading', data: null, error: null })
    try {
      const data = await api.getAuditLog(token)
      setState({ status: 'success', data, error: null })
    } catch (error) {
      if (oidc && (error.status === 401 || /^(invalid token|token expired)/.test(error.message))) signOutLocal()
      setState({ status: 'error', data: null, error })
    }
  }

  async function signInAndFetch() {
    setState({ status: 'loading', data: null, error: null })
    try {
      const { token } = await api.getDevToken(subject, role)
      await fetchLog(token)
    } catch (error) {
      setState({ status: 'error', data: null, error })
    }
  }

  // Back from the login redirect: load the log straight away.
  useEffect(() => {
    if (session) fetchLog(session.token)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const roleInfo = ROLES[role]

  return (
    <div data-testid="audit-trail-content" className="stack">
      <PageHead title="Audit trail">
        Every deployment decision is chained to the one before it, so any edit to history is detectable. Only
        reviewers and approvers may read it.
      </PageHead>

      {oidc ? (
        <section className="card" data-testid="oidc-panel">
          <h3>Sign in</h3>
          {authError && <div role="alert" data-testid="auth-error">{authError}</div>}
          {session ? (
            <>
              <p className="sub">
                Signed in as <b data-testid="signed-in-user">{session.claims.preferred_username || session.claims.sub}</b>.
                Your roles (shown for information; the server decides access):{' '}
                {(session.claims.realm_access?.roles || []).filter((r) => r in ROLES).map((r) => (
                  <Badge key={r} tone="info">{ROLES[r].label}</Badge>
                )) }
              </p>
              <div className="form-row">
                <button onClick={() => fetchLog(session.token)} data-testid="fetch-audit-log">Reload log</button>
                <button onClick={logout} data-testid="sign-out">Sign out</button>
              </div>
            </>
          ) : (
            <>
              <p className="sub">Sign in with your MLShield account. You will be sent to the identity provider and brought back here.</p>
              <button onClick={login} data-testid="sign-in">Sign in</button>
            </>
          )}
        </section>
      ) : (
      <section className="card">
        <h3>Sign in</h3>
        <p className="sub">Demo sign-in only. There is no identity provider in this project, so pick any role.</p>
        <div className="form-row">
          <label className="field">
            Name
            <input value={subject} onChange={(e) => setSubject(e.target.value)} data-testid="subject-input" />
          </label>
          <label className="field">
            Role
            <select value={role} onChange={(e) => setRole(e.target.value)} data-testid="role-select">
              {Object.entries(ROLES).map(([key, r]) => (
                <option key={key} value={key}>{r.label}</option>
              ))}
            </select>
          </label>
          <button onClick={signInAndFetch} data-testid="fetch-audit-log">
            {state.status === 'loading' ? 'Loading...' : 'Sign in and view log'}
          </button>
        </div>
        <p className={`hint ${roleInfo.canView ? 'allowed' : 'denied'}`}>
          {roleInfo.canView
            ? `${roleInfo.label} is allowed to view the audit log.`
            : `${roleInfo.label} is not allowed to view the audit log. Try it to see a real access denial.`}
        </p>
      </section>
      )}

      {state.status === 'idle' && (
        <section className="card empty">
          <b>No log loaded yet</b>
          Sign in above to fetch the audit trail from the backend.
        </section>
      )}

      {state.status === 'loading' && <p data-testid="audit-loading" className="muted" role="status">Checking permissions and loading the log...</p>}

      {state.status === 'error' && (
        <div role="alert" data-testid="audit-error">
          {state.error.status === 403
            ? `Access denied: ${state.error.message}`
            : `Could not load the audit log: ${state.error.message}`}
        </div>
      )}

      {state.status === 'success' && (
        <section className="card" data-testid="audit-log-table">
          <div className={`banner ${state.data.chain_valid ? 'ok' : 'bad'}`}>
            <strong>{state.data.chain_valid ? 'Chain intact' : 'Chain broken'}</strong>
            <span>
              {state.data.chain_valid
                ? `${state.data.n_entries} entries, no tampering detected.`
                : `${state.data.n_entries} entries, but at least one was altered after it was written.`}
            </span>
          </div>
          {state.data.entries.length === 0 ? (
            <div className="empty"><b>The log is empty</b>Decisions will appear here as models are evaluated.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>#</th><th>Who</th><th>Role</th><th>What happened</th><th>When</th></tr>
                </thead>
                <tbody>
                  {state.data.entries.map((entry) => (
                    <tr key={entry.seq}>
                      <td className="mono">{entry.seq}</td>
                      <td className="nowrap">{entry.actor}</td>
                      <td><Badge tone="info">{entry.role}</Badge></td>
                      <td><Badge tone={actionTone(entry.action)}>{entry.action}</Badge></td>
                      <td className="nowrap" title={entry.timestamp}>{formatTime(entry.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
