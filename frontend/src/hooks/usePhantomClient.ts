import { useMemo } from 'react'
import { PhantomGatewayClient } from '../api/gatewayClient'

const IS_DEV = import.meta.env.DEV
const DEV_TOKEN = import.meta.env.VITE_DEV_TOKEN

// Defined first so _singleton can reference it without hoisting issues.
export const getStoredAuthToken = (): string | null => {
  if (IS_DEV && DEV_TOKEN) {
    return DEV_TOKEN
  }
  try {
    return localStorage.getItem('phantom_auth_token') ?? sessionStorage.getItem('phantom_auth_token')
  } catch {
    return null
  }
}

// Singleton client — created once per app, not per render.
// This is critical: if a new instance is created each render, every
// useCallback wrapping client methods changes identity, causing
// usePaginatedQuery / useEffect to re-fetch infinitely (page freeze).
const _singleton = new PhantomGatewayClient(
  import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080',
  getStoredAuthToken,
)

export function usePhantomClient(): PhantomGatewayClient {
  // useMemo with [] ensures the same reference across all renders of any component.
  // Using the module-level singleton guarantees identity stability across component trees.
  return useMemo(() => _singleton, [])
}

