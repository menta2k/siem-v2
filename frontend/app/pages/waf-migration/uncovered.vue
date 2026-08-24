<script setup lang="ts">
import type { WafUncoveredGroup } from '~/composables/useApi'
import { DEFAULT_WAF_HOURS } from '~/lib/wafMigration'
import { usePrefs } from '~/composables/usePrefs'

const { wafUncovered } = useApi()
const { dateTime } = usePrefs()
const hours = ref(DEFAULT_WAF_HOURS)
const host = ref('')
// Frozen at load so the counts and every drill-down share one window.
const appliedHours = ref(DEFAULT_WAF_HOURS)
const appliedHost = ref('')
const groups = ref<WafUncoveredGroup[]>([])
const truncated = ref(false)
const loading = ref(false)
const error = ref('')
const open = ref<string | null>(null)

function rowKey(g: WafUncoveredGroup) { return `${g.violation}|${g.request_host}|${g.request_method}` }

async function load() {
  loading.value = true; error.value = ''; open.value = null
  appliedHours.value = hours.value; appliedHost.value = host.value
  try {
    const q: Record<string, string> = { hours: String(appliedHours.value) }
    if (appliedHost.value) q.host = appliedHost.value
    const res = await wafUncovered(q)
    groups.value = res.groups ?? []
    truncated.value = res.truncated
  } catch (e) {
    error.value = toDisplayMessage(e, 'The uncovered gaps could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <v-container class="py-4" style="max-width:1200px">
    <MigrationStageHeader
      :step="1" title="Uncovered by Cloudflare"
      definition="F5 blocked it, and no Cloudflare rule saw it — the coverage gaps."
      action="Write a Cloudflare rule for each row. Nothing here is deployed for you."
      v-model:hours="hours" v-model:host="host" :loading="loading" @apply="load"
    />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-alert v-if="truncated" type="warning" variant="tonal" density="compact" class="mb-3">
      The window held more than the scan cap; counts are a floor.
    </v-alert>
    <v-card>
      <v-progress-linear v-if="loading" indeterminate color="primary" />
      <v-card-text v-if="!loading && !groups.length" class="text-center py-8">
        <v-icon icon="mdi-shield-check" color="success" size="40" class="mb-2" />
        <div>Nothing uncovered in this window — Cloudflare saw everything F5 blocked.</div>
        <div class="text-caption text-medium-emphasis mt-1">Only requests ingested after this feature deployed are considered.</div>
      </v-card-text>
      <v-table v-else density="compact">
        <thead>
          <tr>
            <th>F5 violation</th><th>Host</th><th>Method</th>
            <th class="text-right">Requests</th><th class="text-right">Paths</th><th class="text-right">Clients</th>
            <th>Last seen</th><th style="width:24px" />
          </tr>
        </thead>
        <tbody>
          <template v-for="g in groups" :key="rowKey(g)">
            <tr style="cursor:pointer" @click="open = open === rowKey(g) ? null : rowKey(g)">
              <td class="text-caption font-weight-medium">
                {{ g.violation }}
                <v-chip v-if="g.cloudflare_allowlisted > 0" size="x-small" color="warning" variant="tonal" class="ml-1">
                  {{ g.cloudflare_allowlisted }} allowed by a CF rule
                </v-chip>
              </td>
              <td class="text-caption">{{ g.request_host }}</td>
              <td class="text-caption">{{ g.request_method }}</td>
              <td class="text-right">{{ g.requests }}</td>
              <td class="text-right">{{ g.paths }}</td>
              <td class="text-right">{{ g.clients }}</td>
              <td class="text-caption text-no-wrap">{{ dateTime(g.last_seen) }}</td>
              <td><v-icon :icon="open === rowKey(g) ? 'mdi-chevron-up' : 'mdi-chevron-down'" size="small" /></td>
            </tr>
            <tr v-if="open === rowKey(g)">
              <td colspan="8" class="pa-0">
                <MigrationSamples
                  :hours="appliedHours" :violation="g.violation" :host="g.request_host" :method="g.request_method"
                  f5-verdict="blocked" cf-verdict="allowed"
                />
                <v-divider />
                <ExpressionTester
                  :hours="appliedHours"
                  :selector="{ violation: g.violation, host: g.request_host, method: g.request_method, f5_verdict: 'blocked', cf_verdict: 'allowed' }"
                />
              </td>
            </tr>
          </template>
        </tbody>
      </v-table>
    </v-card>
  </v-container>
</template>
