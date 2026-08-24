<script setup lang="ts">
import type { WafRuleAgreement } from '~/composables/useApi'
import { readingLabel } from '~/lib/wafMigration'
import { usePrefs } from '~/composables/usePrefs'

/**
 * Stages 2 & 3: one Cloudflare rule per row, with the three F5 counts kept
 * separate (never merged) and a reading. Expanding shows the requests.
 * `sampleF5Verdict` is which F5 outcome the drill-down should show.
 */
defineProps<{
  rules: WafRuleAgreement[]
  hours: number
  minCorrelated: number
  sampleF5Verdict: string
}>()
const { dateTime } = usePrefs()
const open = ref<string | null>(null)
function toggle(id: string) { open.value = open.value === id ? null : id }
function pct(n: number, total: number) { return total > 0 ? Math.round((n / total) * 100) : 0 }
</script>

<template>
  <v-table density="compact">
    <thead>
      <tr>
        <th>Cloudflare rule</th><th>Host</th><th class="text-right">Correlated</th>
        <th class="text-right">F5 blocked</th><th class="text-right">F5 flagged</th><th class="text-right">F5 allowed</th>
        <th style="width:180px">Reading</th><th>Last seen</th><th style="width:24px" />
      </tr>
    </thead>
    <tbody>
      <template v-for="rule in rules" :key="rule.rule_id">
        <tr style="cursor:pointer" @click="toggle(rule.rule_id)">
          <td class="text-caption"><code>{{ rule.rule_id }}</code></td>
          <td class="text-caption">{{ rule.request_host || `${rule.hosts} hosts` }}</td>
          <td class="text-right">{{ rule.correlated }}</td>
          <td class="text-right">{{ rule.f5_blocked }}</td>
          <td class="text-right">{{ rule.f5_flagged }}</td>
          <td class="text-right">{{ rule.f5_allowed }}</td>
          <td>
            <template v-if="rule.reading === 'insufficient'">
              <span class="text-caption text-medium-emphasis">{{ rule.correlated }} of {{ minCorrelated }} requests</span>
            </template>
            <template v-else>
              <v-chip size="x-small" :color="readingLabel(rule.reading).color" variant="tonal" label>{{ readingLabel(rule.reading).text }}</v-chip>
              <div class="d-flex mt-1" style="height:5px;border-radius:3px;overflow:hidden">
                <div :style="{ width: pct(rule.f5_blocked, rule.correlated) + '%' }" class="bg-success" />
                <div :style="{ width: pct(rule.f5_flagged, rule.correlated) + '%' }" class="bg-warning" />
                <div :style="{ width: pct(rule.f5_allowed, rule.correlated) + '%' }" class="bg-error" />
              </div>
            </template>
          </td>
          <td class="text-caption text-no-wrap">{{ dateTime(rule.last_seen) }}</td>
          <td><v-icon :icon="open === rule.rule_id ? 'mdi-chevron-up' : 'mdi-chevron-down'" size="small" /></td>
        </tr>
        <tr v-if="open === rule.rule_id">
          <td colspan="9" class="pa-0">
            <MigrationSamples
              :hours="hours" :rule-id="rule.rule_id"
              :f5-verdict="sampleF5Verdict" cf-verdict="monitored"
            />
          </td>
        </tr>
      </template>
    </tbody>
  </v-table>
</template>
