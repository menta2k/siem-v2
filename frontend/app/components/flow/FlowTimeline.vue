<script setup lang="ts">
import { actionColor } from '~/plugins/vuetify'
import { layerLabel, type Flow } from '~/composables/useApi'

const props = defineProps<{ flow: Flow }>()

// Missing layers are rendered as explicit gaps rather than omitted. "We never
// heard from the WAF" and "the WAF allowed it" are different facts and must
// never look the same.
/**
 * Whether a layer's verdict differs from the majority on this request.
 *
 * "DataDome challenged what everyone else allowed" is the signal this system
 * exists to surface. Marking it explicitly means the reader does not have to
 * notice that two chips are different colours.
 */
function disagrees(event: { verdict: { action: string } }): boolean {
  const actions = props.flow.events.map((e) => e.verdict.action)
  const counts = new Map<string, number>()
  for (const a of actions) counts.set(a, (counts.get(a) ?? 0) + 1)
  if (counts.size < 2) return false
  const majority = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]
  return event.verdict.action !== majority
}

const timeline = computed(() => {
  const order = ['edge', 'bot_management', 'app_firewall', 'origin']
  return order.map((layer) => {
    const event = props.flow.events.find((e) => e.layer === layer)
    return { layer, event, missing: !event }
  })
})
</script>

<template>
  <v-card class="mb-4">
    <v-card-title class="d-flex align-center ga-2">
      <span>Request flow</span>
      <VerdictBadge :action="flow.effective_outcome" />
      <v-chip v-if="flow.completeness !== 'complete'" color="warning" size="small" variant="outlined">
        {{ flow.completeness }}
      </v-chip>
      <v-spacer />
      <ConfidenceChip
        :method="flow.correlation_method"
        :confidence="flow.correlation_confidence"
        :bridged="flow.bridged"
        :completeness="flow.completeness"
      />
    </v-card-title>

    <v-card-text>
      <v-timeline side="end" density="compact" truncate-line="both">
        <v-timeline-item
          v-for="step in timeline"
          :key="step.layer"
          :dot-color="step.missing ? 'grey-darken-2' : actionColor(step.event!.verdict.action)"
          :icon="step.missing ? 'mdi-help' : undefined"
          size="small"
        >
          <template #opposite>
            <span class="text-caption">
              {{ step.event ? new Date(step.event.event_time).toISOString().slice(11, 23) : '—' }}
            </span>
          </template>

          <div v-if="step.missing" class="text-medium-emphasis" data-test="missing-layer">
            <strong>{{ layerLabel(step.layer) }}</strong>
            <div class="text-caption">No record received from this layer</div>
          </div>

          <div v-else data-test="layer-step">
            <div class="d-flex align-center ga-2">
              <strong>{{ layerLabel(step.layer) }}</strong>
              <VerdictBadge
                :action="step.event!.verdict.action"
                :mapped="step.event!.verdict.mapped"
                :rule-name="step.event!.verdict.rule_name"
                :disagreeing="disagrees(step.event!)"
                size="x-small"
              />
              <!--
                Only the flow's terminating layer gets this chip. Several layers
                may each report a terminating ACTION, but only the first one in
                causal order actually ended the request; the rest never saw it or
                were advisory. Showing the chip per-event would claim the request
                was terminated more than once.
              -->
              <v-chip v-if="step.layer === flow.terminating_layer" color="error" size="x-small" variant="outlined">
                terminated here
              </v-chip>
              <v-chip
                v-else-if="step.event!.verdict.terminating"
                color="secondary" size="x-small" variant="outlined"
                title="This layer reported a terminating action, but the request was already ended upstream"
              >
                superseded
              </v-chip>
            </div>
            <div v-if="step.event!.verdict.rule_id" class="text-caption">
              rule {{ step.event!.verdict.rule_id }}
              <span v-if="step.event!.verdict.rule_name"> — {{ step.event!.verdict.rule_name }}</span>
            </div>
            <div v-if="step.event!.verdict.score !== undefined && step.event!.verdict.score !== null" class="text-caption">
              score {{ step.event!.verdict.score }}
            </div>
          </div>
        </v-timeline-item>
      </v-timeline>

      <v-alert
        v-if="flow.data_quality_flags?.length"
        type="warning" variant="tonal" density="compact" class="mt-2"
        data-test="quality-flags"
      >
        <div class="text-caption">
          Data quality: {{ flow.data_quality_flags.join(', ') }}
        </div>
      </v-alert>
    </v-card-text>
  </v-card>
</template>
