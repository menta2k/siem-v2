<script setup lang="ts">
import type { WafSample } from '~/composables/useApi'
import { wafVerdictColor } from '~/lib/wafMigration'
import { usePrefs } from '~/composables/usePrefs'

/**
 * The evidence panel a stage row expands into: real requests behind the count,
 * each with BOTH vendors' verdicts, Cloudflare's attack score, and a per-request
 * OWASP/CRS explainer. Attacker-controlled path/query/user-agent are always
 * interpolated, never v-html.
 */
const props = defineProps<{
  hours: number
  violation?: string
  ruleId?: string
  host?: string
  method?: string
  f5Verdict?: string
  cfVerdict?: string
}>()
const { wafSamples } = useApi()
const { dateTime } = usePrefs()
// The flow drawer lives in the layout; opening it shows the full cross-vendor
// timeline and the raw Cloudflare + F5/WAF records behind this one request.
const { show: openFlow } = useFlowDrawer()
const samples = ref<WafSample[]>([])
const loading = ref(false)
const error = ref('')
// Which rows have their OWASP explainer open. The component mounts (and fetches)
// only when a row is expanded, so a big sample list stays one request.
const expanded = ref<Set<string>>(new Set())

function toggle(id: string) {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}

async function load() {
  loading.value = true; error.value = ''
  try {
    const query: Record<string, string> = { hours: String(props.hours), limit: '20' }
    if (props.violation) query.violation = props.violation
    if (props.ruleId) query.rule_id = props.ruleId
    if (props.host) query.host = props.host
    if (props.method) query.method = props.method
    if (props.f5Verdict) query.f5_verdict = props.f5Verdict
    if (props.cfVerdict) query.cf_verdict = props.cfVerdict
    const res = await wafSamples(query)
    samples.value = res.samples ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'The sample requests could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <div>
    <v-progress-linear v-if="loading" indeterminate color="primary" />
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="ma-2">{{ error }}</v-alert>
    <div v-if="!loading && !samples.length" class="text-caption text-medium-emphasis pa-3">
      No individual requests are retained for this group in the window (they may have aged past retention).
    </div>
    <v-table v-else density="compact">
      <thead>
        <tr><th>Time</th><th>Request</th><th>Client</th><th>F5</th><th>Cloudflare</th><th /></tr>
      </thead>
      <tbody>
        <template v-for="sm in samples" :key="sm.flow_id">
          <tr>
            <td class="text-caption text-no-wrap">{{ dateTime(sm.event_time) }}</td>
            <td class="text-caption">
              <span class="font-weight-medium">{{ sm.request_method }}</span>
              <code class="text-caption">{{ sm.request_path }}<template v-if="sm.request_query">?{{ sm.request_query }}</template></code>
              <div class="text-medium-emphasis">{{ sm.request_host }}</div>
              <div v-if="sm.user_agent" class="text-medium-emphasis text-truncate" style="max-width: 340px" :title="sm.user_agent">{{ sm.user_agent }}</div>
            </td>
            <td class="text-caption">
              {{ sm.client_ip }}<span v-if="sm.country" class="text-medium-emphasis"> · {{ sm.country }}</span>
              <div v-if="sm.client_asn" class="text-medium-emphasis">AS{{ sm.client_asn }}</div>
            </td>
            <td>
              <v-chip size="x-small" :color="wafVerdictColor(sm.f5_verdict)" variant="tonal" label>{{ sm.f5_verdict || '—' }}</v-chip>
              <div v-if="sm.f5_violations?.length" class="text-caption text-medium-emphasis mt-1">{{ sm.f5_violations.join(', ') }}</div>
            </td>
            <td>
              <v-chip size="x-small" :color="wafVerdictColor(sm.cloudflare_verdict)" variant="tonal" label>{{ sm.cloudflare_verdict || '—' }}</v-chip>
              <div v-if="sm.cloudflare_rule_name" class="text-caption text-medium-emphasis mt-1">{{ sm.cloudflare_rule_name }}</div>
              <div v-else-if="sm.cloudflare_rule_id" class="text-caption text-medium-emphasis mt-1"><code>{{ sm.cloudflare_rule_id }}</code></div>
              <WafScore :sample="sm" class="mt-1" />
            </td>
            <td class="text-no-wrap">
              <v-btn
                size="x-small"
                variant="text"
                prepend-icon="mdi-file-search-outline"
                @click="openFlow(sm.flow_id)"
              >
                Evidence
              </v-btn>
              <v-btn
                size="x-small"
                variant="text"
                :prepend-icon="expanded.has(sm.flow_id) ? 'mdi-chevron-up' : 'mdi-shield-search'"
                @click="toggle(sm.flow_id)"
              >
                OWASP
              </v-btn>
            </td>
          </tr>
          <tr v-if="expanded.has(sm.flow_id)">
            <td colspan="6" class="pa-0">
              <div class="bg-surface-variant">
                <OwaspExplain :flow-id="sm.flow_id" />
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </v-table>
  </div>
</template>
