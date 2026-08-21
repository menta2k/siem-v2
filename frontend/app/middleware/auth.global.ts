/**
 * Global auth guard.
 *
 * This is a client-only SPA (ssr: false), and the session is restored in
 * plugins/session.client.ts BEFORE any page or middleware runs — so by the time
 * this executes, isAuthenticated reflects the real state (a live refresh cookie
 * has already been redeemed, or there genuinely is no session).
 *
 * Without this, an unauthenticated visitor got the full app shell — dashboard,
 * search, nav — with every API call silently 401ing, instead of being sent to
 * sign in. A console must not render its authenticated surface to someone who
 * is not.
 */
const PUBLIC_PREFIXES = ['/login', '/invite']

export default defineNuxtRouteMiddleware((to) => {
  // Dev builds authenticate by IMPERSONATION: useApi sends the selected identity
  // string as the bearer with no real session, so isAuthenticated is false even
  // though every call works. Enforcing a redirect there would break the identity
  // switcher and the local workflow. Real-session auth is a production concern.
  if (import.meta.dev) return

  const isPublic = PUBLIC_PREFIXES.some(p => to.path === p || to.path.startsWith(p + '/'))

  const { isAuthenticated } = useAuth()
  if (isAuthenticated.value) {
    // An authenticated user has no reason to sit on the login page.
    if (to.path === '/login') return navigateTo('/')
    return
  }

  if (isPublic) return
  // Preserve where they were headed so sign-in returns them there.
  return navigateTo({ path: '/login', query: { redirect: to.fullPath } })
})
