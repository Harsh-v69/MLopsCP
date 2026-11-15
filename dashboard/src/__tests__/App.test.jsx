import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App'
import { api } from '../api'
import { signOutLocal } from '../auth'

vi.mock('../api')

const b64 = (o) => btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const devToken = (sub, role) =>
  `${b64({ alg: 'HS256' })}.${b64({ sub, role, exp: Math.floor(Date.now() / 1000) + 600 })}.sig`

beforeEach(() => {
  signOutLocal()
  api.getSecurityGate.mockResolvedValue({
    decision: 'PASS', security_score: 90, data_score: 90, model_score: 90, dependency_score: 90,
    integrity_component: 1, details: {},
  })
})
afterEach(() => vi.clearAllMocks())

describe('App sign-in gate', () => {
  it('shows only the sign-in panel, and fetches nothing, while signed out', () => {
    render(<App />)
    expect(screen.getByTestId('sign-in-panel')).toBeInTheDocument()
    expect(api.getSecurityGate).not.toHaveBeenCalled()
    expect(api.getModelCard).not.toHaveBeenCalled()
  })

  it('stays gated on every tab', () => {
    render(<App />)
    for (const tab of ['audit', 'card', 'explain']) {
      fireEvent.click(screen.getByTestId(`tab-${tab}`))
      expect(screen.getByTestId('sign-in-panel')).toBeInTheDocument()
    }
    expect(api.getAuditLog).not.toHaveBeenCalled()
  })

  it('signs in with the chosen role, shows who and what role, then signs out again', async () => {
    api.getDevToken.mockResolvedValue({ token: devToken('alice', 'APPROVER') })
    render(<App />)
    fireEvent.change(screen.getByTestId('role-select'), { target: { value: 'APPROVER' } })
    fireEvent.click(screen.getByTestId('dev-sign-in'))

    await waitFor(() => expect(screen.getByTestId('session-chip')).toBeInTheDocument())
    expect(api.getDevToken).toHaveBeenCalledWith('alice', 'APPROVER')
    expect(screen.getByTestId('signed-in-user')).toHaveTextContent('alice')
    expect(screen.getByTestId('session-chip')).toHaveTextContent('Approver')
    await waitFor(() => expect(api.getSecurityGate).toHaveBeenCalled())

    act(() => signOutLocal())
    expect(screen.getByTestId('sign-in-panel')).toBeInTheDocument()
  })

  it('reports a failed sign-in instead of showing pages', async () => {
    api.getDevToken.mockRejectedValue(new Error('Not Found'))
    render(<App />)
    fireEvent.click(screen.getByTestId('dev-sign-in'))
    await waitFor(() => expect(screen.getByTestId('auth-error')).toHaveTextContent('Not Found'))
    expect(screen.queryByTestId('session-chip')).not.toBeInTheDocument()
  })
})
