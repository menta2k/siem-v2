<script setup lang="ts">
import type { WafSample } from '~/composables/useApi'
import { attackBand } from '~/lib/wafMigration'

/**
 * Cloudflare's WAF attack score for one sample.
 *
 * THE SCALE IS INVERTED — 1 is certainly an attack, 100 certainly clean — so the
 * number never travels without a word beside it. Nothing renders when the score
 * is absent (this deployment's Logpush job may not ship it) or zero (unscored).
 */
const props = defineProps<{ sample: WafSample }>()

const band = computed(() => attackBand(props.sample.attack_score))

// Only the sub-scores that are themselves in attack territory are worth showing;
// a SQLi hit reads 4 for SQLi and 98 for XSS, and the 98s are noise.
const drivers = computed(() =>
  [
    { label: 'SQLi', score: props.sample.sqli_score },
    { label: 'XSS', score: props.sample.xss_score },
    { label: 'RCE', score: props.sample.rce_score },
  ].filter((d): d is { label: string, score: number } =>
    d.score !== undefined && d.score > 0 && d.score <= 50),
)
</script>

<template>
  <div v-if="band" class="d-flex align-center flex-wrap ga-1">
    <v-chip :color="band.color" size="x-small" variant="tonal" label>
      {{ sample.attack_score }}/100 {{ band.label }}
    </v-chip>
    <v-chip
      v-for="d in drivers"
      :key="d.label"
      color="error"
      size="x-small"
      variant="outlined"
      label
    >
      {{ d.label }} {{ d.score }}
    </v-chip>
  </div>
</template>
