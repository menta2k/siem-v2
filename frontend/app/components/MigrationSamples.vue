<script setup lang="ts">
import type { WafSample } from '~/composables/useApi'
import { wafVerdictColor } from '~/lib/wafMigration'
import { usePrefs } from '~/composables/usePrefs'

/**
 * The evidence panel a stage row expands into: real requests behind the count.
 * Attacker-controlled path/query are always interpolated, never v-html.
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
const samples = ref<WafSample[]>([])
const loading = ref(false)
const error = ref('')

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
        <tr><th>Time</th><th>Request</th><th>Client</th><th>F5</th><th>Cloudflare</th></tr>
      </thead>
      <tbody>
        <tr v-for="sm in samples" :key="sm.flow_id">
          <td class="text-caption text-no-wrap">{{ dateTime(sm.event_time) }}</td>
          <td class="text-caption">
            <span class="font-weight-medium">{{ sm.request_method }}</span>
            <code class="text-caption">{{ sm.request_path }}<template v-if="sm.request_query">?{{ sm.request_query }}</template></code>
            <div class="text-medium-emphasis">{{ sm.request_host }}</div>
          </td>
          <td class="text-caption">{{ sm.client_ip }}<span v-if="sm.country" class="text-medium-emphasis"> · {{ sm.country }}</span></td>
          <td>
            <v-chip size="x-small" :color="wafVerdictColor(sm.f5_verdict)" variant="tonal" label>{{ sm.f5_verdict || '—' }}</v-chip>
            <div v-if="sm.f5_violations?.length" class="text-caption text-medium-emphasis mt-1">{{ sm.f5_violations.join(', ') }}</div>
          </td>
          <td>
            <v-chip size="x-small" :color="wafVerdictColor(sm.cloudflare_verdict)" variant="tonal" label>{{ sm.cloudflare_verdict || '—' }}</v-chip>
            <div v-if="sm.cloudflare_rule_id" class="text-caption text-medium-emphasis mt-1"><code>{{ sm.cloudflare_rule_id }}</code></div>
          </td>
        </tr>
      </tbody>
    </v-table>
  </div>
</template>
