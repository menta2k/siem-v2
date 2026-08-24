<script setup lang="ts">
import type { WafOwaspResult } from '~/composables/useApi'
import { crsCategory, crsSeverityColor } from '~/lib/wafMigration'

/**
 * Why the Core Rule Set makes of one request what it does: the CRS rules that
 * fired, and the anomaly score against the block threshold. Cloudflare's managed
 * OWASP ruleset reports only "949110: anomaly score exceeded" and never which
 * rules built it — this recovers them, since the managed ruleset IS the CRS.
 *
 * Evidence only, and replayed against the request as reconstructed from the
 * flow — the note says what that misses.
 */
const props = defineProps<{ flowId: string }>()
const { wafOwasp } = useApi()

const data = ref<WafOwaspResult | null>(null)
const loading = ref(false)
const error = ref('')

async function load() {
  loading.value = true; error.value = ''
  try {
    data.value = await wafOwasp({ flow_id: props.flowId })
  } catch (e) {
    error.value = toDisplayMessage(e, 'The OWASP reading could not be produced.')
  } finally {
    loading.value = false
  }
}
onMounted(load)

const res = computed(() => data.value?.result)

// The Core Rule Set fires dozens of setup, initialization and anomaly-scoring
// rules on every request (900xxx config, 901xxx init, 9xxx13/9xxx14 phase
// markers, 949xxx score evaluators). They carry no severity and no attack tag
// and mean nothing on their own; showing them buries the one rule that made the
// decision. A detection is a rule with a scoring severity or an attack class.
function isDetection(m: { severity: string, tags?: string[] }): boolean {
  const sev = (m.severity || '').toLowerCase()
  if (sev === 'critical' || sev === 'error' || sev === 'warning' || sev === 'notice') return true
  return !!crsCategory(m.tags)
}
const detections = computed(() => (res.value?.matched_rules ?? []).filter(isDetection))
const hiddenCount = computed(() => (res.value?.matched_rules.length ?? 0) - detections.value.length)
</script>

<template>
  <div class="pa-2">
    <v-progress-linear v-if="loading" indeterminate color="primary" />
    <v-alert v-if="error" type="error" variant="tonal" density="compact">{{ error }}</v-alert>

    <template v-if="res">
      <div class="d-flex align-center flex-wrap ga-2 mb-2">
        <v-chip :color="res.would_block ? 'error' : 'success'" size="small" variant="flat" label>
          {{ res.would_block ? 'Would block' : 'Would not block' }}
        </v-chip>
        <span class="text-body-2">
          Anomaly score
          <strong :class="res.would_block ? 'text-error' : 'text-success'">{{ res.anomaly_score }}</strong>
          / threshold {{ res.threshold }}
        </span>
        <span class="text-caption text-medium-emphasis">PL{{ res.paranoia_level }}</span>
        <span class="text-caption text-medium-emphasis">{{ data?.ruleset }}</span>
      </div>

      <v-alert
        v-for="(warn, i) in res.warnings ?? []"
        :key="i"
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-1 text-caption"
      >{{ warn }}</v-alert>

      <div v-if="!detections.length" class="text-caption text-medium-emphasis">
        No Core Rule Set detection rule fired — only setup and scoring rules, which every request trips.
      </div>
      <v-table v-else density="compact">
        <thead>
          <tr><th>Rule</th><th>Class</th><th>Severity</th><th>Message</th></tr>
        </thead>
        <tbody>
          <tr v-for="m in detections" :key="m.rule_id">
            <td class="text-caption"><code>{{ m.rule_id }}</code></td>
            <td class="text-caption">
              <v-chip v-if="crsCategory(m.tags)" color="error" size="x-small" variant="tonal" label>
                {{ crsCategory(m.tags) }}
              </v-chip>
            </td>
            <td>
              <v-chip :color="crsSeverityColor(m.severity)" size="x-small" variant="tonal" label>{{ m.severity || '—' }}</v-chip>
            </td>
            <td class="text-caption">
              {{ m.message }}
              <div v-if="m.data" class="text-medium-emphasis"><code>{{ m.data }}</code></div>
            </td>
          </tr>
        </tbody>
      </v-table>

      <div v-if="hiddenCount > 0" class="text-caption text-medium-emphasis mt-1">
        {{ hiddenCount }} CRS setup and scoring rules that fire on every request are not shown.
      </div>
      <div class="text-caption text-medium-emphasis mt-2">{{ data?.reconstruction_note }}</div>
    </template>
  </div>
</template>
