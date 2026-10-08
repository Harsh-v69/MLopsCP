import { useState } from 'react'
import { api } from '../api'
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

  async function signInAndFetch() {
    setState({ status: 'loading', data: null, error: null })
    try {
      const { token } = await api.getDevToken(subject, role)
      const data = await api.getAuditLog(token)
      setState({ status: 'success', data, error: null })
    } catch (error) {
      setState({ status: 'error', data: null, error })
    }
  }

  const roleInfo = ROLES[role]

  return (
    <div data-testid="audit-trail-content" className="stack">
      <PageHead title="Audit trail">
        Every deployment decision is chained to the one before it, so any edit to history is detectable. Only
        reviewers and approvers may read it.
      </PageHead>

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
