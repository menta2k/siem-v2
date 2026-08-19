/**
 * The authenticated session.
 *
 * The access token lives in MEMORY ONLY and dies with the page — the refresh
 * token in its httpOnly cookie is what survives a reload, and the first API
 * call after one silently refreshes. localStorage is never used for either:
 * it would put a credential where any XSS can read it.
 */
export interface SessionUser {
  principal_id: string
  email: string
  tenant_id: string
  role: string
  permissions: string[]
}

/**
 * The signed-out marker prevents a race v1 hit in production: logout revokes
 * the refresh token, but a background refresh already in flight can land after
 * it and quietly sign the user back in. The marker makes sign-out sticky until
 * the next deliberate login.
 */
const SIGNED_OUT_KEY = 'siem.signedOut'

export function useAuth() {
  const config = useRuntimeConfig()
  const base = config.public.apiBase

  const accessToken = useState<string | null>('auth-access', () => null)
  const user = useState<SessionUser | null>('auth-user', () => null)
  const challengeToken = useState<string | null>('auth-challenge', () => null)
  const provisioningUri = useState<string | null>('auth-enroll-uri', () => null)

  const isAuthenticated = computed(() => !!accessToken.value && !!user.value)
  const awaitingMfa = computed(() => !!challengeToken.value)
  const enrolling = computed(() => !!provisioningUri.value)

  const can = computed(() => {
    const perms = new Set(user.value?.permissions ?? [])
    return {
      viewAudit: perms.has('view_audit'),
      export: perms.has('export'),
      viewSensitive: perms.has('view_sensitive'),
      manageUsers: perms.has('manage_users'),
      manageSources: perms.has('manage_sources'),
      manageRetention: perms.has('manage_retention'),
    }
  })

  function markSignedOut(v: boolean) {
    if (!import.meta.client) return
    if (v) sessionStorage.setItem(SIGNED_OUT_KEY, '1')
    else sessionStorage.removeItem(SIGNED_OUT_KEY)
  }
  function isSignedOut(): boolean {
    return import.meta.client && sessionStorage.getItem(SIGNED_OUT_KEY) === '1'
  }

  /**
   * Step one. Normally the session moves to the MFA step; when the backend
   * runs with the dev skip-MFA flag it completes here and returns true.
   */
  async function login(email: string, password: string): Promise<boolean> {
    const res: any = await $fetch(`${base}/auth/login`, {
      method: 'POST', body: { email, password }, credentials: 'include',
    })
    if (res.access_token) {
      accessToken.value = res.access_token
      user.value = res.user
      challengeToken.value = null
      provisioningUri.value = null
      markSignedOut(false)
      return true
    }
    challengeToken.value = res.challenge_token
    provisioningUri.value = res.enroll ? res.provisioning_uri : null
    return false
  }

  /** Step two: the TOTP code completes the session. */
  async function verifyMfa(code: string) {
    const res: any = await $fetch(`${base}/auth/mfa`, {
      method: 'POST',
      body: { challenge_token: challengeToken.value, code },
      credentials: 'include',
    })
    accessToken.value = res.access_token
    user.value = res.user
    challengeToken.value = null
    provisioningUri.value = null
    markSignedOut(false)
  }

  /**
   * Silent refresh from the cookie. Returns whether a session was recovered.
   * Honours the signed-out marker: a deliberate logout must not be undone by
   * an automatic refresh.
   */
  async function refresh(): Promise<boolean> {
    if (isSignedOut()) return false
    try {
      const res: any = await $fetch(`${base}/auth/refresh`, {
        method: 'POST', credentials: 'include',
      })
      accessToken.value = res.access_token
      user.value = res.user
      return true
    } catch {
      return false
    }
  }

  async function logout() {
    markSignedOut(true)
    try {
      await $fetch(`${base}/auth/logout`, { method: 'POST', credentials: 'include' })
    } catch {
      // Revocation failing server-side must not leave the user visibly signed
      // in; the local session is cleared regardless and the marker holds.
    }
    accessToken.value = null
    user.value = null
    challengeToken.value = null
    provisioningUri.value = null
  }

  return {
    accessToken, user, isAuthenticated, awaitingMfa, enrolling, provisioningUri,
    can, login, verifyMfa, refresh, logout,
  }
}
