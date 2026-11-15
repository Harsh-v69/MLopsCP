import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import AuditTrail from '../AuditTrail'
import { api } from '../../api'

vi.mock('../../api')

describe('AuditTrail', () => {
  it('loads the audit log on open and renders real entries', async () => {
    api.getAuditLog.mockResolvedValue({
      chain_valid: true,
      n_entries: 2,
      entries: [
        { seq: 0, actor: 'system', role: 'SYSTEM', action: 'security_gate_evaluated', timestamp: '2026-01-01T00:00:00Z' },
        { seq: 1, actor: 'alice', role: 'APPROVER', action: 'deployment_approved', timestamp: '2026-01-01T00:01:00Z' },
      ],
    })

    render(<AuditTrail />)
    await waitFor(() => expect(screen.getByTestId('audit-log-table')).toBeInTheDocument())

    expect(screen.getByText('deployment_approved')).toBeInTheDocument()
    expect(screen.getByText('Chain intact')).toBeInTheDocument()
  })

  it('shows a real 403 denial for an unauthorized role, not a silent empty table', async () => {
    const denied = new Error('no role permits view_audit_log')
    denied.status = 403
    api.getAuditLog.mockRejectedValue(denied)

    render(<AuditTrail />)
    await waitFor(() => expect(screen.getByTestId('audit-error')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('Access denied')
    expect(screen.queryByTestId('audit-log-table')).not.toBeInTheDocument()
  })
})
