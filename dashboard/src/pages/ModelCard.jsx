import { useCallback, useState } from 'react'
import { api } from '../api'
import { useFetch } from '../useFetch'
import { Badge, ErrorBox, PageHead, Skeleton } from '../ui'

// The backend (src/transparency/model_card.py) can mark EITHER a whole
// section (e.g. training_data) OR an individual field as unavailable with
// the same {"status": "not available"} shape - a missing source file
// renders as this, never a guessed/omitted value. Both levels need the
// same check.
function isUnavailable(value) {
  return value && typeof value === 'object' && value.status === 'not available'
}

function Field({ label, value, children }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      {children ?? (
        isUnavailable(value) || value === undefined || value === null
          ? <span className="muted">not available</span>
          : <span className="mono">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
      )}
    </div>
  )
}

function YesNo({ label, value, yes, no }) {
  return (
    <Field label={label}>
      <Badge tone={value ? 'pass' : 'fail'}>{value ? yes : no}</Badge>
    </Field>
  )
}

function Section({ title, sub, data, render, className = '' }) {
  return (
    <section className={`card ${className}`}>
      <h3>{title}</h3>
      {sub && <p className="sub">{sub}</p>}
      {isUnavailable(data) ? <p className="muted">not available</p> : render(data)}
    </section>
  )
}

const GATE_TONE = { PASS: 'pass', BORDERLINE: 'warn', FAIL: 'fail' }

export default function ModelCard() {
  const [attempt, setAttempt] = useState(0)
  const fetcher = useCallback(() => api.getModelCard(), [])
  const { status, data, error } = useFetch(fetcher, [attempt])

  if (status === 'loading')
    return (
      <div data-testid="modelcard-loading" className="stack" role="status">
        <p className="muted">Generating Model Card from the live pipeline files. This includes a fresh Security Gate run, so it can take a while.</p>
        <Skeleton height={110} />
        <div className="grid grid-2"><Skeleton height={200} /><Skeleton height={200} /></div>
      </div>
    )
  if (status === 'error')
    return <ErrorBox testId="modelcard-error" title="Could not generate the Model Card" error={error} onRetry={() => setAttempt((n) => n + 1)} />

  const { identity, intended_use, training_data, performance, security, governance, generated_at } = data
  const perf = isUnavailable(performance) ? performance : performance?.kddtest_plus
  const gate = security.security_gate

  return (
    <div data-testid="modelcard-content" className="stack">
      <PageHead title="Model Card">
        A plain summary of what this model is for, how it was built, and how it scored. Generated fresh from the
        real pipeline files at {generated_at}, so it cannot drift out of date.
      </PageHead>

      <section className="card">
        <div className="form-row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: 20 }}>{identity.model_name}</h3>
            <p className="sub" style={{ margin: 0 }}>Version id (first 12 characters of the artifact checksum)</p>
          </div>
          <Badge tone="info" large>{identity.model_version}</Badge>
        </div>
        <div className="field-row" style={{ marginTop: 10, alignItems: 'flex-start' }}>
          <span className="field-label">Intended use</span>
          <span style={{ maxWidth: '60ch', textAlign: 'right' }}>{intended_use.task}</span>
        </div>
        <div className="field-row" style={{ alignItems: 'flex-start' }}>
          <span className="field-label">Out of scope</span>
          <span className="muted" style={{ maxWidth: '60ch', textAlign: 'right' }}>{intended_use.out_of_scope}</span>
        </div>
      </section>

      <div className="grid grid-2">
        <Section
          title="Training data"
          sub="What the model learned from."
          data={training_data}
          render={(d) => (
            <>
              <Field label="Dataset" value={d.dataset} />
              <Field label="Training rows" value={d.train_rows} />
              <Field label="Test rows" value={d.test_rows} />
              <Field label="Split fingerprint" value={d.split_hash} />
            </>
          )}
        />
        <Section
          title="Governance"
          sub="Is the decision history trustworthy?"
          data={governance}
          render={(g) => (
            <>
              <Field label="Audit log entries" value={g.audit_log_entries} />
              <YesNo label="Audit log chain valid" value={g.audit_log_chain_valid} yes="Valid" no="Broken" />
            </>
          )}
        />
      </div>

      <Section
        title="Performance on held-out test data"
        sub="Measured on KDDTest+, which the model never saw during training."
        data={perf}
        render={(d) => (
          <div className="stat-tiles">
            <div className="tile"><div className="k">F1</div><div className="v">{d.f1.toFixed(4)}</div></div>
            <div className="tile"><div className="k">Accuracy</div><div className="v">{d.accuracy.toFixed(4)}</div></div>
            <div className="tile"><div className="k">Precision</div><div className="v">{d.precision.toFixed(4)}</div></div>
            <div className="tile"><div className="k">Recall</div><div className="v">{d.recall.toFixed(4)}</div></div>
          </div>
        )}
      />

      <section className="card">
        <h3>Security</h3>
        <p className="sub">The same checks the Security Gate uses.</p>
        <Field label="Poisoning detector: share of poison caught" value={security.data_scan.recall} />
        <Field label="Poisoning detector: false alarm rate" value={security.data_scan.false_positive_rate} />
        <YesNo label="Model integrity (signature verified)" value={security.model_integrity.signature_verified} yes="Verified" no="Not verified" />
        <Field label="Accuracy lost under adversarial attack" value={security.adversarial_robustness.degradation} />
        <Field label="Known dependency vulnerabilities (live scan)" value={security.dependency_scan.vulnerability_count} />
        <Field label="Security Gate decision">
          <Badge tone={GATE_TONE[gate.decision] || 'info'}>{gate.decision}</Badge>
        </Field>
        <Field label="Security Gate score" value={gate.security_score?.toFixed(2)} />
      </section>
    </div>
  )
}
