<script setup lang="ts">
/**
 * One chip, one state — ordered by how urgently an operator needs to act.
 *
 * The ordering is the whole design, adapted from the predecessor's FeedHealthChip.
 * An invalid credential outranks silence because silence is its CONSEQUENCE:
 * showing "silent" when the real problem is a rotated token sends someone to
 * check the vendor's dashboard instead of fixing the credential.
 *
 * Likewise "awaiting first record" is not "silent". A source nobody has switched
 * on yet and a source that stopped need opposite responses, and conflating them
 * is how an alert becomes one people mute.
 */
const props = defineProps<{
  enabled: boolean
  healthState?: string
  credentialValid?: boolean
  schemaDrift?: boolean
  lastRecordAt?: string | null
}>()

const status = computed(() => {
  if (!props.enabled) {
    return { label: 'Disabled', color: 'grey', icon: 'mdi-pause-circle',
      hint: 'This source is disabled and will reject deliveries.' }
  }
  if (props.credentialValid === false) {
    return { label: 'Credential rejected', color: 'error', icon: 'mdi-key-alert',
      hint: 'A delivery was refused because the credential did not authenticate. Rotate it.' }
  }
  if (props.healthState === 'silent') {
    return { label: 'Silent', color: 'warning', icon: 'mdi-volume-off',
      hint: 'Nothing has arrived within this source’s expected cadence. A silent source looks identical to clean traffic, which is why it alerts.' }
  }
  if (props.schemaDrift) {
    return { label: 'Schema drift', color: 'info', icon: 'mdi-alert-circle-outline',
      hint: 'The provider is sending fields we do not recognise. Ingestion continues and the new fields are preserved.' }
  }
  if (!props.lastRecordAt) {
    return { label: 'Awaiting first record', color: 'secondary', icon: 'mdi-timer-sand',
      hint: 'Configured, but nothing has been received yet. This is not the same as having gone silent.' }
  }
  return { label: 'Healthy', color: 'success', icon: 'mdi-check-circle',
    hint: 'Records are arriving within the expected cadence.' }
})
</script>

<template>
  <v-chip :color="status.color" size="small" variant="tonal" :title="status.hint" data-test="source-health">
    <v-icon :icon="status.icon" start size="x-small" />
    {{ status.label }}
  </v-chip>
</template>
