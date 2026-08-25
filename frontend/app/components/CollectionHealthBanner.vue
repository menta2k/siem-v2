<script setup lang="ts">
/**
 * Collection health, visible on every page.
 *
 * FR-071: a user must never read an incomplete view as a complete one. A silent
 * source looks exactly like clean traffic on a dashboard, so the state of
 * collection has to travel with the data rather than living on a status page
 * nobody opens during an incident.
 */
const props = defineProps<{ compact?: boolean }>()

const { collectionHealth } = useApi()
const health = ref<any>(null)
const failed = ref(false)

async function refresh() {
  try {
    health.value = await collectionHealth()
    failed.value = false
  } catch {
    failed.value = true
  }
}
onMounted(() => {
  refresh()
  const timer = setInterval(refresh, 30000)
  onUnmounted(() => clearInterval(timer))
})

// A readable stage/source name so the badge says WHAT is wrong, not just "Degraded".
const stageLabels: Record<string, string> = {
  ingest_buffer: 'ingest buffer',
  correlation: 'correlation',
}

// Names the specific fault(s) behind a degraded state — a backlogged buffer, a
// silent source, or the reason the collection tier is unreachable — so an
// operator sees the cause on the badge instead of a generic message.
const degradedReason = computed(() => {
  const h = health.value
  if (!h) return ''
  if (h.reason) return String(h.reason)
  const parts: string[] = []
  for (const st of h.stages ?? []) {
    if (st.state === 'backlogged') parts.push(`${stageLabels[st.stage] ?? st.stage} backlogged (${st.backlog_depth?.toLocaleString?.() ?? st.backlog_depth} pending)`)
    else if (st.state === 'zero_output') parts.push(`${stageLabels[st.stage] ?? st.stage} producing no output`)
  }
  const silent = (h.sources ?? []).filter((s: { state?: string }) => s.state === 'silent')
    .map((s: { provider?: string, source_id?: string }) => s.provider || s.source_id)
  if (silent.length) parts.push(`silent: ${silent.join(', ')}`)
  return parts.join('; ')
})

const state = computed(() => {
  if (failed.value) {
    return { color: 'error', icon: 'mdi-alert-circle', label: 'Health unknown',
      hint: 'Collection health could not be read — this view may be incomplete.' }
  }
  if (health.value && health.value.overall !== 'healthy') {
    const why = degradedReason.value
    return { color: 'warning', icon: 'mdi-alert', label: 'Degraded',
      hint: why
        ? `Collection degraded — ${why}. Results may be incomplete.`
        : 'Some sources or stages are not reporting. Results may be incomplete.' }
  }
  return { color: 'success', icon: 'mdi-check-circle', label: 'Collecting',
    hint: 'All sources and stages are reporting.' }
})
</script>

<template>
  <v-chip
    v-if="props.compact"
    :color="state.color" size="small" variant="tonal" :title="state.hint"
    data-test="health-chip" to="/sources"
  >
    <v-icon :icon="state.icon" start size="x-small" />
    {{ state.label }}
  </v-chip>

  <v-alert
    v-else-if="state.color !== 'success'"
    :type="failed ? 'error' : 'warning'" variant="tonal" density="compact" class="mb-3"
    data-test="health-degraded"
  >
    {{ state.hint }}
  </v-alert>
</template>
