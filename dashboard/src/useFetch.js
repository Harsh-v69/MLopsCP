import { useEffect, useState } from 'react'

// Shared loading/error/data states for a fetch-on-mount call. Every page
// uses this so "no stale or fabricated data" (Phase 9 gate) has one place
// to get right: a failed fetch always surfaces a visible error, never a
// blank or last-known-good-looking page.
export function useFetch(fetcher, deps = []) {
  const [state, setState] = useState({ status: 'loading', data: null, error: null })

  useEffect(() => {
    let cancelled = false
    setState({ status: 'loading', data: null, error: null })

    fetcher()
      .then((data) => {
        if (!cancelled) setState({ status: 'success', data, error: null })
      })
      .catch((error) => {
        if (!cancelled) setState({ status: 'error', data: null, error })
      })

    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return state
}
