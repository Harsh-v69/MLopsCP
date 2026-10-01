import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import Explain from '../Explain'
import { api } from '../../api'

vi.mock('../../api')

describe('Explain', () => {
  it('sends the edited record and renders the real SHAP explanation returned', async () => {
    api.explain.mockResolvedValue({
      explanations: [
        {
          label: 'attack',
          attack_probability: 0.94,
          base_rate: 0.4653,
          top_contributing_features: [
            { feature: 'dst_host_srv_count', value: 1.0, shap_value: 0.18 },
            { feature: 'count', value: 5, shap_value: -0.05 },
          ],
        },
      ],
    })

    render(<Explain />)
    fireEvent.click(screen.getByTestId('run-explain'))

    await waitFor(() => expect(screen.getByTestId('explain-result')).toBeInTheDocument())

    expect(screen.getByText('attack', { selector: 'strong' })).toBeInTheDocument()
    expect(screen.getByText('dst_host_srv_count')).toBeInTheDocument()
    expect(screen.getByText('+0.1800')).toBeInTheDocument()
  })

  it('shows a visible error for invalid JSON instead of silently failing', async () => {
    render(<Explain />)
    fireEvent.change(screen.getByTestId('record-textarea'), { target: { value: 'not valid json' } })
    fireEvent.click(screen.getByTestId('run-explain'))

    await waitFor(() => expect(screen.getByTestId('explain-error')).toBeInTheDocument())
    expect(api.explain).not.toHaveBeenCalled()
  })
})
