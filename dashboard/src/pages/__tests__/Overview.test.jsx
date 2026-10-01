import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import Overview from '../Overview'
import { api } from '../../api'

vi.mock('../../api')

describe('Overview', () => {
  it('renders the live Security Gate decision and sub-scores from the backend', async () => {
    api.getSecurityGate.mockResolvedValue({
      decision: 'PASS',
      security_score: 89.07,
      data_score: 84.98,
      model_score: 98.33,
      dependency_score: 80,
      integrity_component: 100,
    })

    render(<Overview />)

    expect(screen.getByTestId('overview-loading')).toBeInTheDocument()

    await waitFor(() => expect(screen.getByTestId('overview-content')).toBeInTheDocument())

    expect(screen.getByTestId('gate-decision')).toHaveTextContent('PASS')
    expect(screen.getByText(/security_score = 89.07/)).toBeInTheDocument()
  })

  it('shows a visible error state on a failed fetch, never a blank page', async () => {
    api.getSecurityGate.mockRejectedValue(new Error('connection refused'))

    render(<Overview />)

    await waitFor(() => expect(screen.getByTestId('overview-error')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('connection refused')
  })
})
