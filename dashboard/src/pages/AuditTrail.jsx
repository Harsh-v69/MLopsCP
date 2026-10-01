import { useState } from 'react'
import { api } from '../api'

// Dev-only "sign in": no real identity provider in this MVP (see
// docs/phase9_transparency_spec.md Part C and docs/phase8_governance_spec.md).
// A role with no view_audit_log permission gets a real 403, not a hidden tab.
const ROLES = ['DATA_ENGINEER', 'ML_ENGINEER', 'SECURITY_REVIEWER', 'APPROVER']

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

  return (
    <div data-testid="audit-trail-content">
      <h2>Audit Trail</h2>
      <p className="muted">
        Dev-only sign-in (no real identity provider in this MVP) — pick a role and fetch. Only
        Security Reviewer and Approver have <code>view_audit_log</code> permission.
      </p>

      <div className="auth-form">
        <label>
          Subject
          <input value={subject} onChange={(e) => setSubject(e.target.value)} data-testid="subject-input" />
        </label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value)} data-testid="role-select">
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <button onClick={signInAndFetch} data-testid="fetch-audit-log">
          Sign in &amp; fetch audit log
        </button>
      </div>

      {state.status === 'loading' && <p data-testid="audit-loading">Loading…</p>}

      {state.status === 'error' && (
        <p role="alert" data-testid="audit-error">
          {state.error.status === 403
            ? `Access denied: ${state.error.message}`
            : `Could not load the audit log: ${state.error.message}`}
        </p>
      )}

      {state.status === 'success' && (
        <div data-testid="audit-log-table">
          <p className="mono">
            chain_valid={String(state.data.chain_valid)}, n_entries={state.data.n_entries}
          </p>
          <table>
            <thead>
              <tr>
                <th>seq</th>
                <th>actor</th>
                <th>role</th>
                <th>action</th>
                <th>timestamp</th>
              </tr>
            </thead>
            <tbody>
              {state.data.entries.map((entry) => (
                <tr key={entry.seq}>
                  <td>{entry.seq}</td>
                  <td>{entry.actor}</td>
                  <td>{entry.role}</td>
                  <td>{entry.action}</td>
                  <td className="mono">{entry.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
