import { useCallback } from 'react'
import { api } from '../api'
import { useFetch } from '../useFetch'

// The backend (src/transparency/model_card.py) can mark EITHER a whole
// section (e.g. training_data) OR an individual field as unavailable with
// the same {"status": "not available"} shape - a missing source file
// renders as this, never a guessed/omitted value. Both levels need the
// same check.
function isUnavailable(value) {
  return value && typeof value === 'object' && value.status === 'not available'
}

function Field({ label, value }) {
  if (isUnavailable(value)) {
    return (
      <div className="field-row">
        <span className="field-label">{label}</span>
        <span className="muted">not available</span>
      </div>
    )
  }
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span className="mono">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
    </div>
  )
}

function Section({ title, data, render }) {
  return (
    <>
      <h3>{title}</h3>
      {isUnavailable(data) ? <p className="muted">not available</p> : render(data)}
    </>
  )
}

export default function ModelCard() {
  const fetcher = useCallback(() => api.getModelCard(), [])
  const { status, data, error } = useFetch(fetcher)

  if (status === 'loading') return <p data-testid="modelcard-loading">Generating Model Card…</p>
  if (status === 'error')
    return (
      <p role="alert" data-testid="modelcard-error">
        Could not generate the Model Card: {error.message}
      </p>
    )

  const { identity, intended_use, training_data, performance, security, governance, generated_at } = data

  return (
    <div data-testid="modelcard-content">
      <h2>Model Card</h2>
      <p className="muted">Generated fresh from live pipeline artifacts at {generated_at}</p>

      <h3>Identity</h3>
      <Field label="Model" value={identity.model_name} />
      <Field label="Version (model artifact md5, first 12)" value={identity.model_version} />

      <h3>Intended use</h3>
      <p>{intended_use.task}</p>
      <p className="muted">Out of scope: {intended_use.out_of_scope}</p>

      <Section
        title="Training data"
        data={training_data}
        render={(d) => (
          <>
            <Field label="Dataset" value={d.dataset} />
            <Field label="Train rows" value={d.train_rows} />
            <Field label="Test rows" value={d.test_rows} />
            <Field label="Split hash" value={d.split_hash} />
          </>
        )}
      />

      <Section
        title="Performance (KDDTest+)"
        data={isUnavailable(performance) ? performance : performance?.kddtest_plus}
        render={(d) => (
          <>
            <Field label="F1" value={d.f1.toFixed(4)} />
            <Field label="Accuracy" value={d.accuracy.toFixed(4)} />
            <Field label="Precision" value={d.precision.toFixed(4)} />
            <Field label="Recall" value={d.recall.toFixed(4)} />
          </>
        )}
      />

      <h3>Security</h3>
      <Field label="Data scan — recall" value={security.data_scan.recall} />
      <Field label="Data scan — false positive rate" value={security.data_scan.false_positive_rate} />
      <Field label="Model integrity (signature verified)" value={security.model_integrity.signature_verified} />
      <Field label="Adversarial degradation" value={security.adversarial_robustness.degradation} />
      <Field label="Dependency vulnerabilities (live scan)" value={security.dependency_scan.vulnerability_count} />
      <Field label="Security Gate decision" value={security.security_gate.decision} />
      <Field label="Security Gate score" value={security.security_gate.security_score?.toFixed(2)} />

      <h3>Governance</h3>
      <Field label="Audit log entries" value={governance.audit_log_entries} />
      <Field label="Audit log chain valid" value={governance.audit_log_chain_valid} />
    </div>
  )
}
