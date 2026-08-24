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

      <div v-if="!res.matched_rules.length" class="text-caption text-medium-emphasis">
        No Core Rule Set rule fired on the reconstructed request.
      </div>
      <v-table v-else density="compact">
        <thead>
          <tr><th>Rule</th><th>Class</th><th>Severity</th><th>Message</th></tr>
        </thead>
        <tbody>
          <tr v-for="m in res.matched_rules" :key="m.rule_id">
            <td class="text-caption"><code>{{ m.rule_id }}</code></td>
            <td class="text-caption">
              <v-chip v-if="crsCategory(m.tags)" color="error" size="x-small" variant="tonal" label>
                {{ crsCategory(m.tags) }}
              </v-chip>
            </td>
            <td>
              <v-chip :color="crsSeverityColor(m.severity)" size="x-small" variant="tonal" label>{{ m.severity }}</v-chip>
            </td>
            <td class="text-caption">
              {{ m.message }}
              <div v-if="m.data" class="text-medium-emphasis"><code>{{ m.data }}</code></div>
            </td>
          </tr>
        </tbody>
      </v-table>

      <div class="text-caption text-medium-emphasis mt-2">{{ data?.reconstruction_note }}</div>
    </template>
  </div>
</template>
