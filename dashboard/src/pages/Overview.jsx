import { useCallback, useState } from 'react'
import { api } from '../api'
import { useFetch } from '../useFetch'
import { Badge, ErrorBox, PageHead, Skeleton } from '../ui'

// Thresholds are locked in docs/security_gate_formula.md. They are only used
// here to draw the scale and pick colours; the decision itself always comes
// from the backend.
const PASS_AT = 80
const BORDERLINE_AT = 50

const VERDICT = {
  PASS: { cls: 'pass', tone: 'pass', title: 'Safe to deploy automatically', body: 'Every check cleared the bar. The decision is written to the audit log.' },
  BORDERLINE: { cls: 'warn', tone: 'warn', title: 'Needs a human approver', body: 'The score is in the grey zone. A named approver must sign off before this model ships.' },
  FAIL: { cls: 'fail', tone: 'fail', title: 'Blocked from deployment', body: 'This release did not meet the security bar. It stays quarantined and an incident is opened.' },
}

const pct = (x) => `${(x * 100).toFixed(1)}%`
const scanAge = (s) => s == null ? null :
  s > 0 ? `Scan result is ${s < 90 ? `${s} seconds` : `${Math.round(s / 60)} minutes`} old (reused for up to an hour)` : 'Scanned just now'
const level = (v) => (v >= PASS_AT ? 'good' : v >= BORDERLINE_AT ? 'mid' : 'low')

function ScoreCard({ title, blurb, weight, value, status, facts }) {
  return (
    <div className="card score-card">
      <div className="top">
        <div>
          <h3>{title}</h3>
          <p className="muted" style={{ margin: 0 }}>{blurb}</p>
        </div>
        <Badge tone="info">weight {weight}</Badge>
      </div>
      <div className="num">{value.toFixed(2)}</div>
      <div className="bar-track" role="img" aria-label={`${title} score ${value.toFixed(0)} out of 100`}>
        <div className={`bar-fill ${level(value)}`} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </div>
      <ul className="facts">
        {status && <li><Badge tone={status.tone}>{status.text}</Badge></li>}
        {facts.map((f) => <li key={f}>{f}</li>)}
      </ul>
    </div>
  )
}

function describe(data) {
  const d = data.details || {}
  const ds = d.data_scan
  const ms = d.model_scan
  const dep = d.dependency_scan

  const dataCard = ds?.status === 'ok'
    ? { status: { tone: 'pass', text: 'Scan completed' }, facts: [`Catches ${pct(ds.recall)} of injected poisoned samples`, `${pct(ds.false_positive_rate)} false alarms on clean data`] }
    : { status: { tone: 'fail', text: 'Scan failed, counted as 0' }, facts: [ds?.error || 'No poisoning evaluation result found'] }

  const modelFacts = []
  if (ms) modelFacts.push(`Model signature: ${ms.integrity_ok ? 'verified' : 'NOT verified'}`)
  if (ms?.status === 'ok') modelFacts.push(`Accuracy under attack ${pct(ms.adversarial_accuracy)} (clean ${pct(ms.clean_accuracy)})`)
  const modelCard = {
    status: ms?.integrity_ok ? { tone: 'pass', text: 'Integrity verified' } : { tone: 'fail', text: 'Integrity check failed' },
    facts: modelFacts.length ? modelFacts : ['No model scan details returned'],
  }

  const depCard = dep?.status === 'ok'
    ? { status: { tone: dep.vulnerability_count === 0 ? 'pass' : 'warn', text: 'Scan completed' }, facts: [`${dep.vulnerability_count} known vulnerabilities in pinned packages`, scanAge(dep.scan_age_seconds)].filter(Boolean) }
    : { status: { tone: 'fail', text: 'Scan failed, counted as 0' }, facts: [dep?.error || 'Dependency scan did not run'] }

  return { dataCard, modelCard, depCard }
}

function reasons(data) {
  const d = data.details || {}
  const out = []
  if (data.integrity_component === 0) {
    out.push({ tone: 'bad', text: 'The model signature does not verify. A model that cannot be proven untampered is always blocked, whatever else it scores.' })
  }
  if (d.dependency_scan?.status === 'failed') {
    out.push({ tone: 'bad', text: 'The dependency scan could not run, so it scores 0. A scan that did not run is never treated as a pass.' })
  }
  if (d.data_scan?.status === 'failed') {
    out.push({ tone: 'bad', text: 'The data poisoning result is missing, so it scores 0.' })
  }
  if (out.length === 0) {
    out.push({ tone: 'ok', text: 'All three scans ran and the model signature verified.' })
  }
  return out
}

function LoadingState() {
  return (
    <div data-testid="overview-loading" className="stack">
      <div className="notice" role="status">
        <span>
          <strong>Running live scans.</strong> The signature check and the dependency audit run fresh on every
          load. The audit builds a temporary environment, so the first load can take a few minutes.
        </span>
      </div>
      <Skeleton height={190} />
      <div className="grid grid-3">
        <Skeleton height={170} />
        <Skeleton height={170} />
        <Skeleton height={170} />
      </div>
    </div>
  )
}

export default function Overview({ onNavigate }) {
  const [attempt, setAttempt] = useState(0)
  const fetcher = useCallback(() => api.getSecurityGate(), [])
  const { status, data, error } = useFetch(fetcher, [attempt])

  if (status === 'loading') return <LoadingState />
  if (status === 'error')
    return <ErrorBox testId="overview-error" title="Could not load the Security Gate result" error={error} onRetry={() => setAttempt((n) => n + 1)} />

  const verdict = VERDICT[data.decision] || VERDICT.FAIL
  const cards = describe(data)
  const score = Math.max(0, Math.min(100, data.security_score))

  return (
    <div data-testid="overview-content" className="stack">
      <PageHead title="Release decision">
        The Security Gate combines three scans into one score and decides whether this model may be deployed.
      </PageHead>

      <section className={`card verdict ${verdict.cls}`}>
        <div>
          <Badge tone={verdict.tone} large data-testid="gate-decision">{data.decision}</Badge>
          <h3>{verdict.title}</h3>
          <p>{verdict.body}</p>
        </div>
        <div>
          <div className="score-big">{data.security_score.toFixed(2)} <small>/ 100</small></div>
          <div className="scale">
            <div className="scale-zones" aria-hidden="true">
              <div className="zone-fail" />
              <div className="zone-warn" />
              <div className="zone-pass" />
            </div>
            <div className="scale-marker" style={{ left: `${score}%` }} aria-hidden="true" />
            <div className="scale-labels" aria-hidden="true">
              <span style={{ left: '25%' }}>Blocked</span>
              <span style={{ left: '65%' }}>Human review</span>
              <span style={{ left: '90%' }}>Pass</span>
            </div>
          </div>
        </div>
      </section>

      <section className="card">
        <h3>What drove this decision</h3>
        <ul className="reasons">
          {reasons(data).map((r) => <li key={r.text} className={r.tone}>{r.text}</li>)}
        </ul>
      </section>

      <div className="grid grid-3">
        <ScoreCard title="Data scan" blurb="Can we spot poisoned training data?" weight="35%" value={data.data_score} {...cards.dataCard} />
        <ScoreCard title="Model scan" blurb="Is the model untampered and robust?" weight="40%" value={data.model_score} {...cards.modelCard} />
        <ScoreCard title="Dependency scan" blurb="Do our packages have known flaws?" weight="25%" value={data.dependency_score} {...cards.depCard} />
      </div>

      <section className="card">
        <details className="how">
          <summary>How the decision is calculated</summary>
          <ul>
            <li>Composite score = 35% data + 40% model + 25% dependency.</li>
            <li>80 or above passes. 50 to 80 goes to a human approver. Below 50 is blocked.</li>
            <li>If the model signature fails, the release is blocked regardless of the score ({data.integrity_component === 0 ? 'this is what happened here' : 'it passed here'}).</li>
            <li>Anyone can recompute it by hand from the three sub-scores:</li>
          </ul>
          <p className="mono" style={{ margin: '10px 0 0' }}>security_score = {data.security_score.toFixed(2)}</p>
        </details>
      </section>

      {onNavigate && (
        <section className="card">
          <h3>Demo guide</h3>
          <p className="sub">Three things worth showing, in order.</p>
          <div className="guide">
            <div className="guide-step">
              <b>See who did what</b>
              Sign in as different roles and watch access get granted or denied.
              <br /><button className="ghost" onClick={() => onNavigate('audit')}>Open Audit Trail</button>
            </div>
            <div className="guide-step">
              <b>Read the Model Card</b>
              A plain-language summary generated from the real pipeline files.
              <br /><button className="ghost" onClick={() => onNavigate('card')}>Open Model Card</button>
            </div>
            <div className="guide-step">
              <b>Ask the model why</b>
              Run a normal request and an attack pattern, then see which features decided it.
              <br /><button className="ghost" onClick={() => onNavigate('explain')}>Open Explain</button>
            </div>
          </div>
        </section>
      )}
    </div>
  )
}
