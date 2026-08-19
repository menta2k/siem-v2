<script setup lang="ts">
import type { Flow } from '~/composables/useApi'

const route = useRoute()
const { getFlow } = useApi()
const flow = ref<Flow | null>(null)
const error = ref('')

onMounted(async () => {
  try {
    flow.value = await getFlow(String(route.params.id))
  } catch (e: any) {
    error.value = toDisplayMessage(e, 'Not found.')
  }
})
</script>

<template>
  <div>
    <v-btn to="/" variant="text" size="small" class="mb-3">← Back to search</v-btn>
    <v-alert v-if="error" type="error" variant="tonal">{{ error }}</v-alert>
    <FlowTimeline v-if="flow" :flow="flow" />

    <v-card v-if="flow">
      <v-card-title class="text-subtitle-1">Contributing records</v-card-title>
      <v-card-text>
        <v-expansion-panels variant="accordion">
          <v-expansion-panel v-for="e in flow.events" :key="e.event_id" :title="`${e.provider} — ${e.layer}`">
            <v-expansion-panel-text>
              <pre class="text-caption" style="white-space:pre-wrap">{{ JSON.stringify(e, null, 2) }}</pre>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card-text>
    </v-card>
  </div>
</template>
