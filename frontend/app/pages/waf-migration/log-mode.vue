<script setup lang="ts">
import type { WafLogModeRule } from '~/composables/useApi'
import { WAF_RANGES, DEFAULT_WAF_HOURS } from '~/lib/wafMigration'
import { usePrefs } from '~/composables/usePrefs'

/**
 * Log-mode activity: every Cloudflare rule currently running in log/monitor
 * mode and how often it fired over the window — the "what are my logging rules
 * doing" overview, before deciding what to enforce. Expanding a row shows the
 * requests it matched.
 */
const { wafLogModeRules } = useApi()
const { dateTime } = usePrefs()
const hours = ref(DEFAULT_WAF_HOURS)
const host = ref('')
const appliedHours = ref(DEFAULT_WAF_HOURS)
const rules = ref<WafLogModeRule[]>([])
const truncated = ref(false)
const loading = ref(false)
const error = ref('')
const open = ref<string | null>(null)
function toggle(id: string) { open.value = open.value === id ? null : id }

const totalMatches = computed(() => rules.value.reduce((n, r) => n + r.matches, 0))

async function load() {
  loading.value = true; error.value = ''
  appliedHours.value = hours.value
  open.value = null
  try {
    const q: Record<string, string> = { hours: String(appliedHours.value) }
    if (host.value) q.host = host.value
    const res = await wafLogModeRules(q)
    rules.value = res.rules ?? []
    truncated.value = res.truncated ?? false
  } catch (e) {
    error.value = toDisplayMessage(e, 'The log-mode activity could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <v-container class="py-4" style="max-width:1200px">
    <v-card class="mb-4" variant="tonal">
      <v-card-text>
        <div class="d-flex align-center flex-wrap ga-3">
          <div class="flex-grow-1" style="min-width:280px">
            <div class="text-overline text-medium-emphasis">WAF migration</div>
            <div class="text-h6">Log-mode activity</div>
            <div class="text-body-2 text-medium-emphasis">
              Cloudflare rules running in log/monitor mode, and how many requests each matched. Nothing here blocks — these rules only observe.
            </div>
          </div>
          <v-select
            v-model="hours" :items="WAF_RANGES" item-title="title" item-value="hours"
            label="Range" density="compact" hide-details style="max-width:170px"
          />
          <v-text-field
            v-model="host" label="Host (optional)" density="compact" hide-details
            clearable style="max-width:220px"
          />
          <v-btn color="primary" :loading="loading" @click="load">Apply</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate color="primary" class="mb-3" />

    <v-card v-if="!loading && !rules.length">
      <v-card-text class="text-center py-8">
        <v-icon icon="mdi-eye-off-outline" size="40" class="mb-2 text-medium-emphasis" />
        <div>No Cloudflare rule matched in log mode in this window.</div>
        <div class="text-caption text-medium-emphasis mt-1">Widen the range, or check that rules are deployed in log/monitor mode.</div>
      </v-card-text>
    </v-card>

    <v-card v-else-if="rules.length">
      <v-card-text class="d-flex align-center py-2 text-caption text-medium-emphasis">
        <span>{{ rules.length }} rule(s) · {{ totalMatches.toLocaleString() }} matches over the last {{ appliedHours }}h</span>
        <v-spacer />
        <span v-if="truncated" class="text-warning">Sampled — counts are a lower bound.</span>
      </v-card-text>
      <v-divider />
      <v-table density="compact">
        <thead>
          <tr>
            <th>Cloudflare rule</th><th>Hosts</th>
            <th class="text-right">Matches</th><th>First seen</th><th>Last seen</th><th style="width:24px" />
          </tr>
        </thead>
        <tbody>
          <template v-for="rule in rules" :key="rule.rule_id">
            <tr style="cursor:pointer" @click="toggle(rule.rule_id)">
              <td class="text-caption">
                <div v-if="rule.rule_name" class="font-weight-medium">{{ rule.rule_name }}</div>
                <code class="text-medium-emphasis">{{ rule.rule_id }}</code>
              </td>
              <td class="text-caption">{{ rule.hosts }}</td>
              <td class="text-right font-weight-medium">{{ rule.matches.toLocaleString() }}</td>
              <td class="text-caption text-no-wrap">{{ dateTime(rule.first_seen) }}</td>
              <td class="text-caption text-no-wrap">{{ dateTime(rule.last_seen) }}</td>
              <td><v-icon :icon="open === rule.rule_id ? 'mdi-chevron-up' : 'mdi-chevron-down'" size="small" /></td>
            </tr>
            <tr v-if="open === rule.rule_id">
              <td colspan="6" class="pa-0">
                <MigrationSamples :hours="appliedHours" :rule-id="rule.rule_id" cf-verdict="monitored" />
              </td>
            </tr>
          </template>
        </tbody>
      </v-table>
    </v-card>
  </v-container>
</template>
