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
const { getFlow, getFlowRaw, identity } = useApi()
const { can } = useAuth()
const flow = ref<Flow | null>(null)
const rawRecords = ref<any[] | null>(null)
const rawError = ref('')
const rawLoading = ref(false)

async function loadRaw() {
  if (!flow.value) return
  rawLoading.value = true; rawError.value = ''
  try {
    const res = await getFlowRaw(flow.value.flow_id)
    rawRecords.value = res.raw ?? []
  } catch (e) {
    rawError.value = toDisplayMessage(e, 'The raw evidence could not be loaded.')
  } finally {
    rawLoading.value = false
  }
}
const loading = ref(false)
const error = ref('')

async function load(id: string) {
  loading.value = true
  error.value = ''
  flow.value = null
  try {
    flow.value = await getFlow(id)
    rawRecords.value = null
    rawError.value = ''
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

        <v-card v-if="can.viewRaw" class="mb-4" data-test="raw-evidence">
          <v-card-title class="d-flex align-center text-subtitle-2">
            Raw evidence
            <v-spacer />
            <v-btn
              v-if="rawRecords === null" size="small" variant="text"
              :loading="rawLoading" @click="loadRaw"
            >Show originals</v-btn>
          </v-card-title>
          <v-card-text v-if="rawRecords !== null">
            <v-alert v-if="rawError" type="error" variant="tonal" density="compact" class="mb-2">{{ rawError }}</v-alert>
            <div v-if="!rawRecords.length" class="text-caption text-medium-emphasis">
              No raw records retained for this flow (they may have passed their retention window).
            </div>
            <v-expansion-panels v-else variant="accordion">
              <v-expansion-panel
                v-for="rec in rawRecords" :key="rec.raw_id"
                :title="`${rec.provider} — original record`"
              >
                <v-expansion-panel-text>
                  <div v-if="rec.masked_fields?.length" class="text-caption text-warning mb-1">
                    Masked before storage: {{ rec.masked_fields.join(', ') }}
                  </div>
                  <pre class="text-caption" style="white-space:pre-wrap; word-break:break-all">{{ rec.payload }}</pre>
                </v-expansion-panel-text>
              </v-expansion-panel>
            </v-expansion-panels>
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
