/**
 * Restores the session BEFORE the app mounts.
 *
 * The access token lives only in memory, so a page reload loses it while the
 * refresh cookie survives. Pages fetch data in their setup; if the refresh ran
 * concurrently (the old onMounted approach) every first fetch raced it, lost,
 * and rendered "Authentication required" until the next navigation. Awaiting
 * here serializes: by the time any page runs, the session is either restored
 * or genuinely absent.
 */
export default defineNuxtPlugin(async () => {
  const { isAuthenticated, refresh } = useAuth()
  if (!isAuthenticated.value) {
    // refresh() resolves false (never throws) with no cookie or after logout.
    await refresh()
  }
})
