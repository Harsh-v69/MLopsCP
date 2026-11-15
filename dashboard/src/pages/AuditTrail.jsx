import { useCallback } from 'react'
import { api } from '../api'
import { useFetch } from '../useFetch'
import { Badge, PageHead } from '../ui'

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
  const fetcher = useCallback(() => api.getAuditLog(), [])
  const state = useFetch(fetcher, [])

  return (
    <div data-testid="audit-trail-content" className="stack">
      <PageHead title="Audit trail">
        Every deployment decision is chained to the one before it, so any edit to history is detectable. Only
        reviewers and approvers may read it.
      </PageHead>

      {state.status === 'loading' && <p data-testid="audit-loading" className="muted" role="status">Checking permissions and loading the log...</p>}

      {state.status === 'error' && (
        <div role="alert" data-testid="audit-error">
          {state.error.status === 403
            ? `Access denied: ${state.error.message}. Sign out and use an account with the Security Reviewer or Approver role.`
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
