/**
 * Shared state for the flow detail drawer.
 *
 * The drawer lives in the LAYOUT rather than in the page. Vuetify's navigation
 * drawers register with the surrounding app layout to reserve their space, and a
 * drawer nested inside `v-main` never registers — it simply does not render,
 * silently and with no error.
 *
 * Keeping the open/close state here means any page can open the drawer without
 * owning it.
 */
export function useFlowDrawer() {
  const open = useState<boolean>('flow-drawer-open', () => false)
  const flowId = useState<string | null>('flow-drawer-id', () => null)

  function show(id: string) {
    flowId.value = id
    open.value = true
  }

  function hide() {
    open.value = false
  }

  return { open, flowId, show, hide }
}
