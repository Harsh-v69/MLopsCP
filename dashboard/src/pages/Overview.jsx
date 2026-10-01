import { useCallback } from 'react'
import { api } from '../api'
import { useFetch } from '../useFetch'

const DECISION_CLASS = {
  PASS: 'decision-pass',
  BORDERLINE: 'decision-borderline',
  FAIL: 'decision-fail',
}

function ScoreBar({ label, weight, value }) {
  return (
    <div className="score-row">
      <div className="score-row-label">
        <span>
          {label} <span className="muted">({weight})</span>
        </span>
        <span className="mono">{value.toFixed(2)}</span>
      </div>
      <div className="bar-track">
        <div className="bar-fill" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </div>
    </div>
  )
}

export default function Overview() {
  const fetcher = useCallback(() => api.getSecurityGate(), [])
  const { status, data, error } = useFetch(fetcher)

  if (status === 'loading') return <p data-testid="overview-loading">Loading live Security Gate result…</p>
  if (status === 'error')
    return (
      <p role="alert" data-testid="overview-error">
        Could not load the Security Gate result: {error.message}
      </p>
    )

  return (
    <div data-testid="overview-content">
      <h2>Security Gate — live result</h2>
      <p className={`decision-pill ${DECISION_CLASS[data.decision] || ''}`} data-testid="gate-decision">
        {data.decision}
      </p>
      <p className="mono">security_score = {data.security_score.toFixed(2)}</p>

      <ScoreBar label="Data scan" weight="weight 0.35" value={data.data_score} />
      <ScoreBar label="Model scan" weight="weight 0.40" value={data.model_score} />
      <ScoreBar label="Dependency scan" weight="weight 0.25" value={data.dependency_score} />

      <p className="muted">
        integrity_component = {data.integrity_component} (0 forces FAIL regardless of score)
      </p>
    </div>
  )
}
