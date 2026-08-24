<script setup lang="ts">
import type { WafRuleAgreement } from '~/composables/useApi'
import { DEFAULT_WAF_HOURS } from '~/lib/wafMigration'

const { wafRules } = useApi()
const hours = ref(DEFAULT_WAF_HOURS)
const host = ref('')
const appliedHours = ref(DEFAULT_WAF_HOURS)
const rules = ref<WafRuleAgreement[]>([])
const minCorrelated = ref(10)
const loading = ref(false)
const error = ref('')

async function load() {
  loading.value = true; error.value = ''
  appliedHours.value = hours.value
  try {
    const q: Record<string, string> = { hours: String(appliedHours.value) }
    if (host.value) q.host = host.value
    const res = await wafRules('false-positives', q)
    rules.value = res.rules ?? []
    minCorrelated.value = res.min_correlated ?? 10
  } catch (e) {
    error.value = toDisplayMessage(e, 'The false-positive rules could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <v-container class="py-4" style="max-width:1200px">
    <MigrationStageHeader
      :step="3" title="Likely false positives"
      definition="A Cloudflare rule in log mode firing on traffic F5 is happy with."
      action="Narrow these rules before enforcing — they would block legitimate traffic."
      v-model:hours="hours" v-model:host="host" :loading="loading" @apply="load"
    />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate color="primary" class="mb-3" />
    <v-card v-if="!loading && !rules.length">
      <v-card-text class="text-center py-8">
        <v-icon icon="mdi-shield-check" color="success" size="40" class="mb-2" />
        <div>No log-mode Cloudflare rule is firing on traffic F5 allows — nothing to fix before enforcing.</div>
      </v-card-text>
    </v-card>
    <v-card v-else-if="!loading">
      <RuleAgreementTable :rules="rules" :hours="appliedHours" :min-correlated="minCorrelated" sample-f5-verdict="allowed" />
    </v-card>
  </v-container>
</template>
