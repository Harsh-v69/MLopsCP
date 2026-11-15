// OIDC authorization-code login with PKCE (RFC 7636), no client secret and no library.
// The access token lives in memory only (never localStorage), so a page reload signs the
// user out; the identity provider's own session makes signing back in instant.
// The browser decodes the token for display only. The API verifies it and decides access.
const ISSUER = import.meta.env.VITE_OIDC_ISSUER || 'http://localhost:8081/realms/mlshield'
const CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID || 'mlshield-dashboard'

// 'oidc' (Docker stack, real login) or 'dev' (local Vite demo against a dev-mode API).
export const authMode = () => import.meta.env.VITE_AUTH_MODE || 'dev'

const KEY = 'mlshield.pkce'
let session = null // { token, claims }
let lastError = null

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export const randomString = (n = 48) => b64url(crypto.getRandomValues(new Uint8Array(n)))

export async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return b64url(new Uint8Array(digest))
}

export function decodeClaims(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)))
  } catch {
    return null
  }
}

const redirectUri = () => `${window.location.origin}/`
const endpoint = (name) => `${ISSUER}/protocol/openid-connect/${name}`

export function buildAuthUrl({ challenge, state }) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: 'openid',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  return `${endpoint('auth')}?${params}`
}

export async function login() {
  const verifier = randomString(64)
  const state = randomString(24)
  sessionStorage.setItem(KEY, JSON.stringify({ verifier, state }))
  window.location.assign(buildAuthUrl({ challenge: await challengeFor(verifier), state }))
}

// Call once at startup, before rendering. Finishes a login if we were just redirected back.
export async function initAuth() {
  const params = new URLSearchParams(window.location.search)
  if (!params.has('code') && !params.has('error')) return
  const saved = JSON.parse(sessionStorage.getItem(KEY) || 'null')
  sessionStorage.removeItem(KEY) // one use only
  window.history.replaceState({}, '', window.location.pathname)

  if (params.has('error')) {
    lastError = `Sign-in failed: ${params.get('error_description') || params.get('error')}`
    return
  }
  if (!saved || saved.state !== params.get('state')) {
    lastError = 'Sign-in failed: the response did not match this browser session (state mismatch).'
    return
  }
  try {
    const res = await fetch(endpoint('token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        code: params.get('code'),
        redirect_uri: redirectUri(),
        code_verifier: saved.verifier,
      }),
    })
    const body = await res.json()
    if (!res.ok || !body.access_token) throw new Error(body.error_description || body.error || res.statusText)
    session = { token: body.access_token, claims: decodeClaims(body.access_token) }
    sessionStorage.setItem('mlshield.tab', 'audit')
  } catch (e) {
    lastError = `Sign-in failed: ${e.message}`
  }
}

export function currentSession() {
  if (session && session.claims && session.claims.exp * 1000 > Date.now()) return session
  session = null
  return null
}

export const takeAuthError = () => {
  const e = lastError
  lastError = null
  return e
}

export function signOutLocal() {
  session = null
}

export function logout() {
  session = null
  const params = new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: redirectUri() })
  window.location.assign(`${endpoint('logout')}?${params}`)
}
