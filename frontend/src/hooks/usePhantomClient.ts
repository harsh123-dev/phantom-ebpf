import { PhantomGatewayClient } from '../api/gatewayClient'

const IS_DEV = import.meta.env.DEV
const DEV_TOKEN = import.meta.env.VITE_DEV_TOKEN

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

export function usePhantomClient(): PhantomGatewayClient {
  return new PhantomGatewayClient(
    import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080',
    getStoredAuthToken
  )
}
