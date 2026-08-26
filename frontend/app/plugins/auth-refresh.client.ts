/**
 * Keeps the in-memory access token fresh for the life of the tab.
 *
 * The token has a short TTL (minutes). session.client.ts restores it ONCE at
 * load, so without this it silently expires mid-session and every request —
 * the health-banner poll, any click — starts returning 401 until the user
 * reloads the page. Instead, schedule a silent refresh shortly BEFORE the token
 * expires, and re-arm after each one.
 *
 * A backgrounded tab has its timers throttled, so the scheduled refresh can be
 * late; on the tab becoming visible again we refresh immediately if the token
 * is close to (or past) expiry. refresh() is single-flight, so the timer and
 * the visibility handler firing together still make just one request.
 */
export default defineNuxtPlugin(() => {
  const { refresh, tokenExp, isAuthenticated } = useAuth()

  // Refresh this long before expiry — enough margin for the request itself and
  // for minor clock differences between the browser and the server.
  const LEAD_MS = 60_000
  let timer: ReturnType<typeof setTimeout> | null = null

  function clear() {
    if (timer) { clearTimeout(timer); timer = null }
  }

  async function refreshNow() {
    clear()
    if (isAuthenticated.value) await refresh()
    schedule()
  }

  function schedule() {
    clear()
    const exp = tokenExp.value
    if (!exp) return // no real session (e.g. dev impersonation): nothing to refresh.
    // Never below a few seconds, so a token already near expiry refreshes
    // promptly rather than scheduling in the past.
    const delay = Math.max(5_000, exp * 1000 - Date.now() - LEAD_MS)
    timer = setTimeout(refreshNow, delay)
  }

  // Re-arm whenever the token (and thus its expiry) changes — login, restore,
  // or a completed refresh.
  watch(tokenExp, schedule, { immediate: true })

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return
    const exp = tokenExp.value
    if (exp && exp * 1000 - Date.now() < LEAD_MS) refreshNow()
  })
})
