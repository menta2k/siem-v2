<script setup lang="ts">
import type { Flow } from '~/composables/useApi'
import { layerLabel } from '~/composables/useApi'

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

// The layer that actually stopped the request: prefer the terminating event on
// the recorded terminating layer, else any terminating verdict. Its verdict
// carries the exact reason a WAF/bot engine blocked.
const blockingEvent = computed(() => {
  const f = flow.value
  if (!f) return null
  const evs = f.events ?? []
  return evs.find(e => e.layer === f.terminating_layer && e.verdict?.terminating)
    ?? evs.find(e => e.verdict?.terminating)
    ?? null
})
const isEnforced = computed(() =>
  ['blocked', 'challenge_failed', 'rate_limited'].includes(flow.value?.effective_outcome ?? ''))

// The single most common point of confusion: a DataDome block. DataDome runs as
// a Cloudflare Worker at the edge, so the 403 is served BY Cloudflare while the
// DECISION was DataDome's — and Cloudflare's own WAF (a separate layer) may have
// allowed the request. Surface a plain-words note whenever that is the case.
const terminatedAtDataDome = computed(() => blockingEvent.value?.layer === 'bot_management')

/** Provider reason (verdict.reason_raw) flattened to display rows, skipping the
 *  noise and empties. Values that are arrays/objects are stringified. */
function reasonRows(raw?: Record<string, unknown>): { key: string, value: string }[] {
  if (!raw) return []
  const skip = new Set([
    'field_family', 'parent_ray', 'subrequest_ray', 'source', 'status', 'subrequest_status', 'request_status',
    // Cloudflare Security* duplicate the structured rule/category shown above.
    'SecurityAction', 'SecurityActions', 'SecurityRuleDescription', 'SecurityRuleID',
    'SecurityRuleIDs', 'SecuritySources',
  ])
  const rows: { key: string, value: string }[] = []
  for (const [k, v] of Object.entries(raw)) {
    if (skip.has(k) || v == null || v === '' || v === 'N/A') continue
    const value = Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v)
    if (value.trim() === '' || value === 'N/A') continue
    rows.push({ key: k.replace(/[_-]+/g, ' '), value })
  }
  return rows
}
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

        <v-card
          v-if="blockingEvent || isEnforced" class="mb-4"
          :color="isEnforced ? 'error' : undefined" variant="tonal"
          data-test="block-reason"
        >
          <v-card-title class="d-flex align-center text-subtitle-2">
            <v-icon icon="mdi-shield-alert-outline" start size="small" />
            Why it was {{ flow.effective_outcome === 'challenge_failed' ? 'challenged' : (flow.effective_outcome || 'stopped') }}
          </v-card-title>
          <v-card-text>
            <div v-if="blockingEvent" class="d-flex align-center flex-wrap ga-2 mb-3">
              <VerdictBadge
                :action="blockingEvent.verdict.action"
                :mapped="blockingEvent.verdict.mapped"
              />
              <span class="text-body-2">
                at <strong>{{ layerLabel(blockingEvent.layer) }}</strong>
                <span class="text-medium-emphasis">({{ blockingEvent.provider }})</span>
              </span>
            </div>
            <div v-else class="text-body-2 mb-2">
              Outcome <strong>{{ flow.effective_outcome }}</strong><span v-if="flow.terminating_layer"> at {{ layerLabel(flow.terminating_layer) }}</span>.
            </div>

            <!-- The "blocked by Cloudflare but terminated at DataDome" explainer. -->
            <v-alert
              v-if="terminatedAtDataDome" density="compact" variant="tonal" color="info"
              class="text-caption mb-3" data-test="datadome-note"
            >
              <div class="d-flex ga-2">
                <v-icon icon="mdi-information-outline" size="small" />
                <div>
                  <strong>DataDome runs as a Cloudflare Worker</strong>, at the edge — so the 403 was
                  served <em>by Cloudflare</em>, but the block was <em>DataDome's</em> decision.
                  Cloudflare's own WAF is a separate layer (see the timeline) and did not block this
                  request; the request reached DataDome precisely because Cloudflare's WAF let it
                  through. It never went on to F5 or the origin.
                </div>
              </div>
            </v-alert>

            <v-table v-if="blockingEvent" density="compact" class="bg-transparent">
              <tbody>
                <tr v-if="blockingEvent.verdict.rule_name || blockingEvent.verdict.rule_id">
                  <td class="text-medium-emphasis" style="width:150px">Rule</td>
                  <td class="text-break">
                    {{ blockingEvent.verdict.rule_name || blockingEvent.verdict.rule_id }}
                    <span v-if="blockingEvent.verdict.rule_name && blockingEvent.verdict.rule_id" class="text-caption text-medium-emphasis">({{ blockingEvent.verdict.rule_id }})</span>
                  </td>
                </tr>
                <tr v-if="blockingEvent.verdict.category">
                  <td class="text-medium-emphasis">Category</td><td class="text-break">{{ blockingEvent.verdict.category }}</td>
                </tr>
                <tr v-if="blockingEvent.verdict.score != null">
                  <td class="text-medium-emphasis">Score</td><td>{{ blockingEvent.verdict.score }}</td>
                </tr>
                <tr v-for="row in reasonRows(blockingEvent.verdict.reason_raw)" :key="row.key">
                  <td class="text-medium-emphasis text-capitalize">{{ row.key }}</td>
                  <td class="text-break">{{ row.value }}</td>
                </tr>
              </tbody>
            </v-table>
            <div
              v-if="blockingEvent && !blockingEvent.verdict.mapped"
              class="text-caption text-warning mt-1"
            >
              The provider reported a value this system does not recognise; shown verbatim above.
            </div>
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
