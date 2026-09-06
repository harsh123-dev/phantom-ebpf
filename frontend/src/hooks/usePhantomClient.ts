/**
 * usePhantomClient — provides the active API client to all components.
 *
 * Client selection order:
 *   1. VITE_USE_MOCK_DATA=true → always use DemoGatewayClient
 *   2. Real API available       → use PhantomGatewayClient (live EC2 / local)
 *   3. Real API unreachable     → auto-fallback to DemoGatewayClient
 *
 * The singleton pattern prevents infinite re-fetch loops that would occur
 * if a new client instance were created on every render.
 */

import { DemoGatewayClient } from '../api/demoGatewayClient'
import { PhantomGatewayClient } from '../api/gatewayClient'

const IS_DEV = import.meta.env.DEV
const DEV_TOKEN = import.meta.env.VITE_DEV_TOKEN as string | undefined
const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true'

export const getStoredAuthToken = (): string | null => {
  if (IS_DEV && DEV_TOKEN) return DEV_TOKEN
  try {
    return localStorage.getItem('phantom_auth_token') ?? sessionStorage.getItem('phantom_auth_token')
  } catch {
    return null
  }
}

// -------------------------------------------------------------------------
// Client singleton — determined once at module load time
// -------------------------------------------------------------------------

/** Shared client instance — either real or demo. */
export type PhantomClient = PhantomGatewayClient | DemoGatewayClient

const _demo = new DemoGatewayClient()

const _real = new PhantomGatewayClient(
  import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080',
  getStoredAuthToken,
  // Use a short connect-timeout (8 s) so the probe below resolves quickly
  8_000,
)

/**
 * Probe the real API once at startup with a short timeout.
 * If it fails for any reason, switch to demo mode for this page load.
 */
let _resolvedClient: PhantomClient | null = null

async function resolveClient(): Promise<PhantomClient> {
  if (_resolvedClient) return _resolvedClient
  if (USE_MOCK) {
    _resolvedClient = _demo
    console.info('[PHANTOM] Demo mode enabled via VITE_USE_MOCK_DATA=true')
    return _resolvedClient
  }
  try {
    const baseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? 'http://localhost:8080'
    const token = getStoredAuthToken()
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
    const controller = new AbortController()
    const id = setTimeout(() => controller.abort(), 4_000)
    const res = await fetch(`${baseUrl}/api/v1/incidents?limit=1`, { headers, signal: controller.signal })
    clearTimeout(id)
    if (res.ok || res.status === 401 || res.status === 403) {
      // 401/403 means the API is alive — auth might need fixing, but it's reachable
      _resolvedClient = _real
      console.info('[PHANTOM] Connected to live API at', baseUrl)
    } else {
      throw new Error(`HTTP ${res.status}`)
    }
  } catch {
    _resolvedClient = _demo
    console.warn('[PHANTOM] Live API unreachable — using demo data (real EC2 evaluation results)')
  }
  return _resolvedClient
}

// Begin resolution immediately so it's ready before components mount
const _clientPromise = resolveClient()

// -------------------------------------------------------------------------
// React hook
// -------------------------------------------------------------------------

import { useEffect, useState } from 'react'

export function usePhantomClient(): PhantomClient {
  const [client, setClient] = useState<PhantomClient>(_resolvedClient ?? _demo)

  useEffect(() => {
    let active = true
    void _clientPromise.then((c) => {
      if (active) setClient(c)
    })
    return () => { active = false }
  }, [])

  return client
}

/** Expose demo client flag for components that want to show a banner. */
export function useIsDemoMode(): boolean {
  const client = usePhantomClient()
  return client instanceof DemoGatewayClient
}
