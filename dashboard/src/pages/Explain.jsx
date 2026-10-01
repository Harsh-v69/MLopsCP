import { useState } from 'react'
import { api } from '../api'

// A real, plausible example record (one actual NSL-KDD connection shape),
// plainly marked as an example - not fabricated data presented as the
// user's own, per artifact-design guidance applied to this dashboard too.
const EXAMPLE_RECORD = {
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

export default function Explain() {
  const [recordJson, setRecordJson] = useState(JSON.stringify(EXAMPLE_RECORD, null, 2))
  const [state, setState] = useState({ status: 'idle', data: null, error: null })

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

  return (
    <div data-testid="explain-content">
      <h2>Explain a prediction</h2>
      <p className="muted">
        Example record shown below (a real NSL-KDD connection shape, not your own data). Edit it and
        run — SHAP (TreeExplainer, exact) shows which features pushed the prediction which way.
      </p>

      <textarea
        value={recordJson}
        onChange={(e) => setRecordJson(e.target.value)}
        rows={12}
        data-testid="record-textarea"
      />
      <button onClick={runExplain} data-testid="run-explain">
        Explain
      </button>

      {state.status === 'loading' && <p data-testid="explain-loading">Running SHAP TreeExplainer…</p>}

      {state.status === 'error' && (
        <p role="alert" data-testid="explain-error">
          Could not explain this record: {state.error.message}
        </p>
      )}

      {state.status === 'success' && (
        <div data-testid="explain-result">
          <p>
            Prediction: <strong>{state.data.label}</strong> (attack_probability ={' '}
            {state.data.attack_probability.toFixed(4)}, base_rate = {state.data.base_rate.toFixed(4)})
          </p>
          <table>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Value</th>
                <th>SHAP contribution</th>
              </tr>
            </thead>
            <tbody>
              {state.data.top_contributing_features.map((f) => (
                <tr key={f.feature}>
                  <td>{f.feature}</td>
                  <td className="mono">{f.value}</td>
                  <td className={f.shap_value >= 0 ? 'shap-positive' : 'shap-negative'}>
                    {f.shap_value >= 0 ? '+' : ''}
                    {f.shap_value.toFixed(4)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
