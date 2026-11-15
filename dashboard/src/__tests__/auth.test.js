import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildAuthUrl,
  challengeFor,
  currentSession,
  decodeClaims,
  initAuth,
  randomString,
  signOutLocal,
  takeAuthError,
} from '../auth'

const b64 = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const jwt = (claims) => `${b64({ alg: 'RS256' })}.${b64(claims)}.sig`

function landOn(search) {
  window.history.replaceState({}, '', `/${search}`)
}

beforeEach(() => {
  sessionStorage.clear()
  signOutLocal()
  takeAuthError()
  landOn('')
})
afterEach(() => vi.restoreAllMocks())

describe('PKCE helpers', () => {
  it('matches the RFC 7636 test vector', async () => {
    expect(await challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    )
  })

  it('makes unguessable, url-safe random strings', () => {
    const a = randomString(48)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(a).not.toBe(randomString(48))
  })

  it('builds an auth URL with PKCE S256, state and no secret', () => {
    const url = new URL(buildAuthUrl({ challenge: 'abc', state: 'xyz' }))
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('code_challenge')).toBe('abc')
    expect(url.searchParams.get('state')).toBe('xyz')
    expect(url.searchParams.get('client_id')).toBe('mlshield-dashboard')
    expect(url.searchParams.has('client_secret')).toBe(false)
  })
})

describe('callback handling', () => {
  it('rejects a state mismatch without calling the token endpoint', async () => {
    sessionStorage.setItem('mlshield.pkce', JSON.stringify({ verifier: 'v', state: 'expected' }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    landOn('?code=c&state=attacker')
    await initAuth()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(currentSession()).toBeNull()
    expect(takeAuthError()).toMatch(/state mismatch/)
    expect(window.location.search).toBe('') // code removed from the address bar
  })

  it('rejects a callback with no saved login attempt', async () => {
    landOn('?code=c&state=s')
    await initAuth()
    expect(currentSession()).toBeNull()
    expect(takeAuthError()).toMatch(/state mismatch/)
  })

  it('reports an error returned by the identity provider', async () => {
    landOn('?error=access_denied&error_description=Nope')
    await initAuth()
    expect(takeAuthError()).toMatch(/Nope/)
  })

  it('exchanges the code with the verifier and keeps the token in memory only', async () => {
    sessionStorage.setItem('mlshield.pkce', JSON.stringify({ verifier: 'the-verifier', state: 's1' }))
    const token = jwt({ sub: 'u1', preferred_username: 'alice', exp: Math.floor(Date.now() / 1000) + 300 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: token }),
    })
    landOn('?code=the-code&state=s1')
    await initAuth()
    const body = fetchSpy.mock.calls[0][1].body
    expect(body.get('code_verifier')).toBe('the-verifier')
    expect(body.get('code')).toBe('the-code')
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(currentSession().claims.preferred_username).toBe('alice')
    expect(JSON.stringify({ ...localStorage })).not.toContain(token)
    expect(sessionStorage.getItem('mlshield.pkce')).toBeNull() // single use
  })

  it('reports a failed token exchange', async () => {
    sessionStorage.setItem('mlshield.pkce', JSON.stringify({ verifier: 'v', state: 's1' }))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      statusText: 'Bad Request',
      json: async () => ({ error_description: 'Code not valid' }),
    })
    landOn('?code=c&state=s1')
    await initAuth()
    expect(currentSession()).toBeNull()
    expect(takeAuthError()).toMatch(/Code not valid/)
  })
})

describe('session', () => {
  it('treats an expired token as signed out', async () => {
    sessionStorage.setItem('mlshield.pkce', JSON.stringify({ verifier: 'v', state: 's1' }))
    const expired = jwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 5 })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, json: async () => ({ access_token: expired }) })
    landOn('?code=c&state=s1')
    await initAuth()
    expect(currentSession()).toBeNull()
  })

  it('decodes claims and returns null for garbage', () => {
    expect(decodeClaims(jwt({ sub: 'x' })).sub).toBe('x')
    expect(decodeClaims('not-a-token')).toBeNull()
  })
})
