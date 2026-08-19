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

const state = computed(() => {
  if (failed.value) {
    return { color: 'error', icon: 'mdi-alert-circle', label: 'Health unknown',
      hint: 'Collection health could not be read — this view may be incomplete.' }
  }
  if (health.value && health.value.overall !== 'healthy') {
    return { color: 'warning', icon: 'mdi-alert', label: 'Degraded',
      hint: 'Some sources or stages are not reporting. Results may be incomplete.' }
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
