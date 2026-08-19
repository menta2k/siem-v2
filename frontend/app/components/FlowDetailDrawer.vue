<script setup lang="ts">
import type { Flow } from '~/composables/useApi'

/**
 * Flow detail in a drawer rather than a page.
 *
 * An analyst working a list is comparing flows, not reading one. Navigating away
 * loses the result set, the scroll position and the filters that produced them,
 * and coming back re-runs the query. A drawer keeps the list underneath, which is
 * what makes "check this one, then the next" actually work.
 */
const { open, flowId } = useFlowDrawer()
const { getFlow, identity } = useApi()
const flow = ref<Flow | null>(null)
const loading = ref(false)
const error = ref('')

async function load(id: string) {
  loading.value = true
  error.value = ''
  flow.value = null
  try {
    flow.value = await getFlow(id)
  } catch (e) {
    error.value = toDisplayMessage(e, 'This flow could not be loaded.')
  } finally {
    loading.value = false
  }
}

watch(flowId, (id) => { if (id && open.value) load(id) })
watch(open, (isOpen) => { if (isOpen && flowId.value) load(flowId.value) })
// A change of identity can change what is visible, so a stale flow must not
// linger in the drawer after the viewer changes.
watch(identity, () => { if (flowId.value && open.value) load(flowId.value) })
</script>

<template>
  <v-navigation-drawer
    v-model="open" location="right" temporary :width="720"
    data-test="flow-drawer"
  >
    <v-toolbar density="comfortable" color="surface">
      <v-toolbar-title class="text-subtitle-1">Request flow</v-toolbar-title>
      <v-spacer />
      <v-btn
        v-if="flowId" :to="`/flows/${encodeURIComponent(flowId)}`"
        variant="text" size="small" prepend-icon="mdi-open-in-new"
        title="Open as a full page, for sharing a link"
      >
        Permalink
      </v-btn>
      <v-btn icon="mdi-close" variant="text" @click="open = false" />
    </v-toolbar>
    <v-divider />

    <div class="pa-4">
      <v-progress-linear v-if="loading" indeterminate color="primary" class="mb-3" />
      <v-alert v-if="error" type="error" variant="tonal">{{ error }}</v-alert>

      <template v-if="flow">
        <FlowTimeline :flow="flow" />

        <v-card class="mb-4">
          <v-card-title class="text-subtitle-2">Request</v-card-title>
          <v-card-text>
            <v-table density="compact">
              <tbody>
                <tr><td class="text-medium-emphasis" style="width:150px">Host</td><td>{{ flow.request?.host || '—' }}</td></tr>
                <tr><td class="text-medium-emphasis">Path</td><td class="text-break">{{ flow.request?.path || '—' }}</td></tr>
                <tr><td class="text-medium-emphasis">Method</td><td>{{ flow.request?.method || '—' }}</td></tr>
                <tr><td class="text-medium-emphasis">Client</td><td>{{ flow.client?.ip || '—' }}</td></tr>
                <tr><td class="text-medium-emphasis">Country</td><td>{{ flow.client?.country || '—' }}</td></tr>
                <tr><td class="text-medium-emphasis">User agent</td><td class="text-break text-caption">{{ flow.client?.user_agent || '—' }}</td></tr>
                <tr>
                  <td class="text-medium-emphasis">Correlation key</td>
                  <td class="text-caption">{{ flow.correlation_key }}</td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>

        <v-card>
          <v-card-title class="text-subtitle-2">Contributing records</v-card-title>
          <v-card-text>
            <v-expansion-panels variant="accordion">
              <v-expansion-panel
                v-for="e in flow.events" :key="e.event_id"
                :title="`${e.provider} — ${e.layer}`"
              >
                <v-expansion-panel-text>
                  <pre class="text-caption" style="white-space:pre-wrap">{{ JSON.stringify(e, null, 2) }}</pre>
                </v-expansion-panel-text>
              </v-expansion-panel>
            </v-expansion-panels>
          </v-card-text>
        </v-card>
      </template>
    </div>
  </v-navigation-drawer>
</template>
