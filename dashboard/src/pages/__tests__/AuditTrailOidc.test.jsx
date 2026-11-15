import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AuditTrail from '../AuditTrail'

afterEach(() => vi.unstubAllEnvs())

describe('AuditTrail in oidc mode', () => {
  it('offers a real sign-in, not the demo role picker, when signed out', () => {
    vi.stubEnv('VITE_AUTH_MODE', 'oidc')
    render(<AuditTrail />)
    expect(screen.getByTestId('sign-in')).toBeInTheDocument()
    expect(screen.queryByTestId('role-select')).not.toBeInTheDocument()
  })
})
