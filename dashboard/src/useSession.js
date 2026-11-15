import { useSyncExternalStore } from 'react'
import { currentSession, subscribe } from './auth'

// The signed-in session (or null). Re-renders on sign-in, sign-out and token rejection.
export const useSession = () => useSyncExternalStore(subscribe, currentSession)
