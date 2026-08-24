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

const bucket = (reading: string) => rules.value.filter(r => r.reading === reading)
const sections = computed(() => [
  { key: 'ready', title: 'Ready to enforce', subtitle: 'Cloudflare agrees with F5 — safe to turn to block.', f5: 'blocked', rows: bucket('ready') },
  { key: 'disputed', title: 'Disputed — needs a person', subtitle: 'The vendors only half agree.', f5: 'allowed', rows: bucket('disputed') },
  { key: 'insufficient', title: 'Still accumulating evidence', subtitle: 'Working, but too few correlated requests to decide.', f5: 'blocked', rows: bucket('insufficient') },
].filter(s => s.rows.length))

async function load() {
  loading.value = true; error.value = ''
  appliedHours.value = hours.value
  try {
    const q: Record<string, string> = { hours: String(appliedHours.value) }
    if (host.value) q.host = host.value
    const res = await wafRules('ready', q)
    rules.value = res.rules ?? []
    minCorrelated.value = res.min_correlated ?? 10
  } catch (e) {
    error.value = toDisplayMessage(e, 'The rule agreement could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <v-container class="py-4" style="max-width:1200px">
    <MigrationStageHeader
      :step="2" title="Ready to enforce"
      definition="A Cloudflare rule in log mode whose decisions match what F5 independently blocked."
      action="Turn a 'ready' rule from log to block on Cloudflare."
      v-model:hours="hours" v-model:host="host" :loading="loading" @apply="load"
    />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate color="primary" class="mb-3" />
    <v-card v-if="!loading && !sections.length">
      <v-card-text class="text-center py-8">
        <v-icon icon="mdi-shield-sync-outline" size="40" class="mb-2 text-medium-emphasis" />
        <div>No Cloudflare rules are running in log mode in this window.</div>
        <div class="text-caption text-medium-emphasis mt-1">Widen the range, or deploy a candidate rule in log mode (see step 1).</div>
      </v-card-text>
    </v-card>
    <v-card v-for="s in sections" :key="s.key" class="mb-4">
      <v-card-title class="text-subtitle-2">{{ s.title }}</v-card-title>
      <v-card-subtitle class="text-caption">{{ s.subtitle }}</v-card-subtitle>
      <RuleAgreementTable :rules="s.rows" :hours="appliedHours" :min-correlated="minCorrelated" :sample-f5-verdict="s.f5" />
    </v-card>
  </v-container>
</template>
