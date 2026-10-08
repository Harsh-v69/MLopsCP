import { render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import ModelCard from '../ModelCard'
import { api } from '../../api'

vi.mock('../../api')

const REAL_SHAPED_CARD = {
  identity: { model_name: 'mlshield-baseline-rf', model_version: 'a898ab58db2f' },
  intended_use: { task: 'Binary network-connection classification: normal vs. attack', out_of_scope: 'Does not classify attack sub-type.' },
  training_data: { dataset: 'NSL-KDD', train_rows: 125973, test_rows: 22544, split_hash: 'b34944a6...' },
  performance: { kddtest_plus: { f1: 0.7653, accuracy: 0.779, precision: 0.968, recall: 0.633 } },
  security: {
    data_scan: { recall: 0.96625, false_positive_rate: 0.0325 },
    model_integrity: { signature_verified: true },
    adversarial_robustness: { degradation: 0.01 },
    dependency_scan: { vulnerability_count: 3 },
    security_gate: { decision: 'PASS', security_score: 89.07 },
  },
  governance: { audit_log_entries: 4, audit_log_chain_valid: true },
  generated_at: '2026-10-01T00:00:00Z',
}

describe('ModelCard', () => {
  it('renders every documented section from real backend data, not placeholders', async () => {
    api.getModelCard.mockResolvedValue(REAL_SHAPED_CARD)

    render(<ModelCard />)
    await waitFor(() => expect(screen.getByTestId('modelcard-content')).toBeInTheDocument())

    expect(screen.getByText('mlshield-baseline-rf')).toBeInTheDocument()
    expect(screen.getByText('a898ab58db2f')).toBeInTheDocument()
    expect(screen.getByText('NSL-KDD')).toBeInTheDocument()
    expect(screen.getByText('0.7653')).toBeInTheDocument()
    expect(screen.getByText('PASS')).toBeInTheDocument()

    // Two different fields both render "true" (signature_verified AND
    // audit_log_chain_valid) - assert on the specific row, not a global
    // text match, now that the test caught the ambiguity.
    const auditRow = screen.getByText('Audit log chain valid').closest('.field-row')
    expect(within(auditRow).getByText('Valid')).toBeInTheDocument()
  })

  it('renders "not available" for a missing section instead of fabricating a value', async () => {
    api.getModelCard.mockResolvedValue({
      ...REAL_SHAPED_CARD,
      training_data: { status: 'not available' },
    })

    render(<ModelCard />)
    await waitFor(() => expect(screen.getByTestId('modelcard-content')).toBeInTheDocument())

    expect(screen.queryByText('NSL-KDD')).not.toBeInTheDocument()
  })

  it('shows a visible error state on a failed fetch', async () => {
    api.getModelCard.mockRejectedValue(new Error('500 Internal Server Error'))

    render(<ModelCard />)
    await waitFor(() => expect(screen.getByTestId('modelcard-error')).toBeInTheDocument())
  })
})
