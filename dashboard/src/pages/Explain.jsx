import { useState } from 'react'
import { api } from '../api'
import { Badge, PageHead } from '../ui'

// Illustrative NSL-KDD-shaped connections, labelled as examples in the UI.
// The label shown after "Explain" always comes from the real model.
const BASE = {
  duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF',
  src_bytes: 232, dst_bytes: 8153, land: 0, wrong_fragment: 0, urgent: 0,
  hot: 0, num_failed_logins: 0, logged_in: 1, num_compromised: 0,
  root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 0,
  num_shells: 0, num_access_files: 0, num_outbound_cmds: 0, is_host_login: 0,
  is_guest_login: 0, count: 5, srv_count: 5, serror_rate: 0, srv_serror_rate: 0,
  rerror_rate: 0, srv_rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0,
  srv_diff_host_rate: 0, dst_host_count: 30, dst_host_srv_count: 255,
  dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 0,
  dst_host_srv_diff_host_rate: 0, dst_host_serror_rate: 0, dst_host_srv_serror_rate: 0,
  dst_host_rerror_rate: 0, dst_host_srv_rerror_rate: 0,
}

const PRESETS = {
  normal: {
    label: 'Ordinary web request',
    hint: 'A logged-in HTTP connection that completes normally.',
    record: BASE,
  },
  flood: {
    label: 'SYN flood pattern',
    hint: 'Hundreds of half-open connections to many services, none completing. The classic denial-of-service signature.',
    record: {
      ...BASE, service: 'private', flag: 'S0', src_bytes: 0, dst_bytes: 0, logged_in: 0,
      count: 255, srv_count: 18, serror_rate: 1, srv_serror_rate: 1,
      same_srv_rate: 0.07, diff_srv_rate: 0.06, dst_host_count: 255, dst_host_srv_count: 18,
      dst_host_same_srv_rate: 0.07, dst_host_diff_srv_rate: 0.07,
      dst_host_serror_rate: 1, dst_host_srv_serror_rate: 1,
    },
  },
}

const pretty = (r) => JSON.stringify(r, null, 2)

function Contributions({ features }) {
  const max = Math.max(...features.map((f) => Math.abs(f.shap_value)), 1e-9)
  return (
    <div>
      <div className="contrib axis" aria-hidden="true">
        <span />
        <div className="axis-labels">
          <span>toward normal</span>
          <span>toward attack</span>
        </div>
        <span />
      </div>
      {features.map((f) => {
        const width = `${(Math.abs(f.shap_value) / max) * 50}%`
        const up = f.shap_value >= 0
        return (
          <div className="contrib" key={f.feature}>
            <div className="contrib-name">
              <span>{f.feature}</span>
              <span className="mono muted">value {f.value}</span>
            </div>
            <div className="contrib-bar" aria-hidden="true">
              <div className={`contrib-fill ${up ? 'up' : 'down'}`} style={{ width }} />
            </div>
            <span className={`mono contrib-num ${up ? 'shap-positive' : 'shap-negative'}`}>
              {up ? '+' : ''}
              {f.shap_value.toFixed(4)}
            </span>
          </div>
        )
      })}
    </div>
  )
}

export default function Explain() {
  const [preset, setPreset] = useState('normal')
  const [recordJson, setRecordJson] = useState(pretty(PRESETS.normal.record))
  const [state, setState] = useState({ status: 'idle', data: null, error: null })

  function choose(key) {
    setPreset(key)
    setRecordJson(pretty(PRESETS[key].record))
    setState({ status: 'idle', data: null, error: null })
  }

  async function runExplain() {
    setState({ status: 'loading', data: null, error: null })
    try {
      const record = JSON.parse(recordJson)
      const result = await api.explain([record])
      setState({ status: 'success', data: result.explanations[0], error: null })
    } catch (error) {
      setState({ status: 'error', data: null, error })
    }
  }

  const result = state.data
  const isAttack = result?.label === 'attack'

  return (
    <div data-testid="explain-content" className="stack">
      <PageHead title="Explain a prediction">
        Pick a network connection and ask the model to classify it. SHAP then shows which features pushed the
        answer toward attack or toward normal.
      </PageHead>

      <section className="card">
        <h3>1. Choose an example</h3>
        <p className="sub">These are illustrative records shaped like the NSL-KDD dataset, not your own traffic.</p>
        <div className="seg" role="group" aria-label="Example connections">
          {Object.entries(PRESETS).map(([key, p]) => (
            <button key={key} className={preset === key ? 'on' : ''} onClick={() => choose(key)} aria-pressed={preset === key}>
              {p.label}
            </button>
          ))}
        </div>
        <p className="muted" style={{ margin: '10px 0 14px' }}>{PRESETS[preset]?.hint}</p>

        <details>
          <summary>Edit the raw record</summary>
          <label className="field" htmlFor="record-json" style={{ marginTop: 8 }}>
            Connection record (JSON)
          </label>
          <textarea
            id="record-json"
            value={recordJson}
            onChange={(e) => setRecordJson(e.target.value)}
            rows={12}
            data-testid="record-textarea"
          />
        </details>

        <div style={{ marginTop: 14 }}>
          <button onClick={runExplain} data-testid="run-explain">
            {state.status === 'loading' ? 'Explaining...' : 'Explain'}
          </button>
        </div>
      </section>

      {state.status === 'idle' && (
        <section className="card empty">
          <b>No prediction yet</b>
          Choose an example and press Explain.
        </section>
      )}

      {state.status === 'loading' && <p data-testid="explain-loading" className="muted" role="status">Running SHAP TreeExplainer...</p>}

      {state.status === 'error' && (
        <div role="alert" data-testid="explain-error">
          Could not explain this record: {state.error.message}
        </div>
      )}

      {state.status === 'success' && (
        <section className="card" data-testid="explain-result">
          <h3>2. The model's answer</h3>
          <p style={{ fontSize: 18, margin: '4px 0 6px' }}>
            Prediction: <strong>{result.label}</strong>{' '}
            <Badge tone={isAttack ? 'fail' : 'pass'}>{isAttack ? 'Suspicious' : 'Looks fine'}</Badge>
          </p>
          <p className="muted" style={{ margin: '0 0 16px' }}>
            Attack probability {result.attack_probability.toFixed(4)}. The model starts from a base rate of{' '}
            {result.base_rate.toFixed(4)} (the share of attacks it saw in training) and the features below move it
            up or down.
          </p>
          <Contributions features={result.top_contributing_features} />
        </section>
      )}
    </div>
  )
}
