<script setup lang="ts">
import type { WafSelector } from '~/composables/useApi'

/**
 * Stage 1 helper: test a candidate Cloudflare expression against this group's
 * real captured requests before writing it anywhere. It never deploys — it
 * says how many of these requests the expression would catch.
 */
const props = defineProps<{ hours: number, selector: WafSelector }>()
const { wafEvaluate } = useApi()
const expression = ref('')
const running = ref(false)
const error = ref('')
const result = ref<any | null>(null)

async function run() {
  if (!expression.value.trim()) return
  running.value = true; error.value = ''; result.value = null
  try {
    result.value = await wafEvaluate({ hours: props.hours, expression: expression.value, selector: props.selector })
  } catch (e) {
    error.value = toDisplayMessage(e, 'The expression could not be evaluated.')
  } finally {
    running.value = false
  }
}

const tested = computed(() => result.value?.results?.length ?? result.value?.tested ?? 0)
const matched = computed(() => result.value?.results?.filter((r: any) => r.matched).length ?? result.value?.matched ?? 0)
const verdict = computed(() => {
  if (!result.value) return null
  if (result.value.expression_valid === false) return { color: 'warning', text: `Invalid expression: ${result.value.parse_error || 'parse error'}` }
  if (tested.value === 0) return { color: 'info', text: result.value.note || 'No requests were available to test.' }
  if (matched.value === tested.value) return { color: 'success', text: `Catches every one of these ${tested.value} requests.` }
  if (matched.value === 0) return { color: 'error', text: `Catches none of these ${tested.value} requests.` }
  return { color: 'warning', text: `Catches ${matched.value} of ${tested.value} — this group holds more than one kind of request.` }
})
</script>

<template>
  <div class="pa-3">
    <div class="text-caption text-medium-emphasis mb-1">
      Test a Cloudflare rule expression against these requests (evidence only — nothing is deployed):
    </div>
    <v-textarea
      v-model="expression" rows="2" density="compact" variant="outlined" auto-grow
      placeholder='e.g. http.request.uri.path contains &quot;/admin&quot;'
      hide-details @keydown.ctrl.enter="run"
    />
    <div class="d-flex align-center ga-2 mt-2">
      <v-btn size="small" color="primary" variant="flat" :loading="running" :disabled="!expression.trim()" @click="run">Test</v-btn>
      <span class="text-caption text-medium-emphasis">Ctrl+Enter</span>
    </div>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-2">{{ error }}</v-alert>
    <v-alert v-else-if="verdict" :type="verdict.color as any" variant="tonal" density="compact" class="mt-2">
      {{ verdict.text }}
      <span v-if="result?.fidelity_note" class="d-block text-caption mt-1">{{ result.fidelity_note }}</span>
    </v-alert>
  </div>
</template>
