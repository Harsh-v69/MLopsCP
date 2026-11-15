import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SignInPanel } from '../SignIn'

afterEach(() => vi.unstubAllEnvs())

describe('SignInPanel in oidc mode', () => {
  it('offers the identity-provider sign-in, not the demo role picker', () => {
    vi.stubEnv('VITE_AUTH_MODE', 'oidc')
    render(<SignInPanel />)
    expect(screen.getByTestId('sign-in')).toBeInTheDocument()
    expect(screen.queryByTestId('role-select')).not.toBeInTheDocument()
  })
})
