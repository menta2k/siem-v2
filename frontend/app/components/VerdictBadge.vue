<script setup lang="ts">
import { actionColor, actionIcon } from '~/plugins/vuetify'

/**
 * One layer's decision, presented consistently everywhere it appears.
 *
 * Two deliberate choices:
 *
 *   - Every badge carries an ICON as well as a colour. Meaning must not rest on
 *     colour alone, both for accessibility and because an operations room monitor
 *     is not a colour-calibrated display.
 *   - Disagreement is marked EXPLICITLY rather than implied by two badges being
 *     different colours. "DataDome challenged what everyone else allowed" is the
 *     signal this system exists to surface, and it should not depend on the
 *     reader noticing a hue.
 */
/**
 * `mapped` and `disagreeing` carry explicit defaults.
 *
 * Vue casts an ABSENT boolean prop to false, so `mapped` left unset would read as
 * "the provider reported something we do not recognise" and stamp every badge in
 * the system with an unmapped marker. The default has to say the safe thing:
 * unless told otherwise, a verdict is mapped.
 */
const props = withDefaults(
  defineProps<{
    action: string
    layer?: string
    provider?: string
    ruleId?: string
    ruleName?: string
    score?: number | null
    /** False when the provider reported something we do not recognise. */
    mapped?: boolean
    /** Set when this layer's verdict differs from the others on the same request. */
    disagreeing?: boolean
    size?: string
  }>(),
  { mapped: true, disagreeing: false },
)

const label = computed(() => {
  const l: Record<string, string> = {
    allowed: 'Allowed',
    logged: 'Detected only',
    rate_limited: 'Rate limited',
    challenged: 'Challenged',
    challenge_passed: 'Challenge passed',
    challenge_failed: 'Challenge failed',
    blocked: 'Blocked',
    unknown: 'Unknown',
  }
  return l[props.action] ?? props.action
})

// "Detected only" needs saying out loud: a layer in detection mode did not
// permit the request, it declined to act, and the distinction is invisible if the
// badge just reads "allowed".
const hint = computed(() => {
  if (props.action === 'logged') {
    return 'This layer detected the request but did not enforce — it was served regardless.'
  }
  if (!props.mapped) {
    return 'This provider reported a decision this system does not recognise. The original value is preserved.'
  }
  return props.ruleName || ''
})
</script>

<template>
  <span class="d-inline-flex align-center ga-1">
    <v-chip
      :color="actionColor(action)"
      :size="size ?? 'small'"
      variant="tonal"
      label
      :title="hint"
      data-test="verdict-badge"
    >
      <v-icon :icon="actionIcon(action)" start size="x-small" />
      {{ label }}
    </v-chip>

    <v-chip
      v-if="!mapped"
      color="purple" :size="size ?? 'x-small'" variant="outlined"
      title="Unrecognised value, surfaced verbatim rather than coerced"
    >
      unmapped
    </v-chip>

    <!-- Marked, not merely coloured differently. -->
    <v-chip
      v-if="disagreeing"
      color="warning" :size="size ?? 'x-small'" variant="outlined"
      title="This layer's verdict differs from the others on this request"
      data-test="disagreement"
    >
      <v-icon icon="mdi-alert-outline" start size="x-small" />
      differs
    </v-chip>
  </span>
</template>
