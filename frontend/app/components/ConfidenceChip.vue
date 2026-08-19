<script setup lang="ts">
/**
 * How much the reader should hesitate before trusting a join.
 *
 * The rule, adapted from the predecessor's hard-won experience: a low-confidence
 * join is shown as a join that MIGHT be wrong — never hidden, and never dressed
 * up as certain. Suppressing it loses a correlation the analyst probably wanted;
 * presenting it as fact teaches them to trust joins that have not earned it.
 *
 * Note what does NOT lower confidence: an exact join spanning several records
 * from one provider. A Worker-protected request legitimately produces more than
 * one Cloudflare row, and treating that as competing candidates warned falsely on
 * the overwhelming majority of exact joins in v1. Competition is only meaningful
 * on a heuristic join, where records genuinely contended for one slot.
 */
const props = defineProps<{
  method: string
  confidence: number
  bridged?: boolean
  completeness?: string
}>()

const state = computed(() => {
  if (props.method === 'exact') {
    return props.bridged
      ? {
          color: 'info',
          label: 'exact · bridged',
          hint: 'Joined on a shared identifier, reached through a record carrying two identifier spaces. No dependence on clock agreement.',
        }
      : {
          color: 'success',
          label: 'exact',
          hint: 'Joined on an identifier every member carries. No dependence on clock agreement.',
        }
  }
  if (props.method === 'heuristic') {
    return {
      color: 'warning',
      label: `heuristic · ${props.confidence.toFixed(2)}`,
      hint: 'Matched on client, host, path, method and time proximity. These records may not belong to the same request.',
    }
  }
  return {
    color: 'grey',
    label: 'uncorrelated',
    hint: 'No join was possible. This record stands alone.',
  }
})
</script>

<template>
  <v-chip :color="state.color" size="small" variant="outlined" :title="state.hint" data-test="confidence">
    {{ state.label }}
  </v-chip>
</template>
