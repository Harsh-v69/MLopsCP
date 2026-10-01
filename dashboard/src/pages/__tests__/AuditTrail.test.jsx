import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import AuditTrail from '../AuditTrail'
import { api } from '../../api'

vi.mock('../../api')

describe('AuditTrail', () => {
  it('fetches a dev token then the audit log, and renders real entries', async () => {
    api.getDevToken.mockResolvedValue({ token: 'fake.jwt.token' })
    api.getAuditLog.mockResolvedValue({
      chain_valid: true,
      n_entries: 2,
      entries: [
        { seq: 0, actor: 'system', role: 'SYSTEM', action: 'security_gate_evaluated', timestamp: '2026-01-01T00:00:00Z' },
        { seq: 1, actor: 'alice', role: 'APPROVER', action: 'deployment_approved', timestamp: '2026-01-01T00:01:00Z' },
      ],
    })

    render(<AuditTrail />)
    fireEvent.click(screen.getByTestId('fetch-audit-log'))

    await waitFor(() => expect(screen.getByTestId('audit-log-table')).toBeInTheDocument())

    expect(api.getDevToken).toHaveBeenCalledWith('alice', 'SECURITY_REVIEWER')
    expect(api.getAuditLog).toHaveBeenCalledWith('fake.jwt.token')
    expect(screen.getByText('deployment_approved')).toBeInTheDocument()
    expect(screen.getByText(/chain_valid=true/)).toBeInTheDocument()
  })

  it('shows a real 403 denial for an unauthorized role, not a silent empty table', async () => {
    api.getDevToken.mockResolvedValue({ token: 'fake.jwt.token' })
    const deniedError = new Error('role DATA_ENGINEER is not permitted to view_audit_log')
    deniedError.status = 403
    api.getAuditLog.mockRejectedValue(deniedError)

    render(<AuditTrail />)
    fireEvent.change(screen.getByTestId('role-select'), { target: { value: 'DATA_ENGINEER' } })
    fireEvent.click(screen.getByTestId('fetch-audit-log'))

    await waitFor(() => expect(screen.getByTestId('audit-error')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('Access denied')
    expect(screen.queryByTestId('audit-log-table')).not.toBeInTheDocument()
  })
})
