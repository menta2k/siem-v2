<script setup lang="ts">
import type { FlowSearch } from '~/composables/useApi'

const props = defineProps<{ modelValue: FlowSearch }>()
const emit = defineEmits<{
  (e: 'update:modelValue', filters: FlowSearch): void
  (e: 'apply'): void
}>()

// A local working copy: filters apply on SUBMIT, not on every keystroke. Firing a
// query per character would put a scan on the store for each prefix of what the
// analyst is typing.
const draft = ref<FlowSearch>({ ...props.modelValue })

watch(() => props.modelValue, (next) => { draft.value = { ...next } }, { deep: true })

const timeRangeOptions = [
  { title: 'Any time', value: '' },
  { title: 'Last 15 minutes', value: '15m' },
  { title: 'Last hour', value: '1h' },
  { title: 'Last 24 hours', value: '24h' },
  { title: 'Last 15 days', value: '15d' },
  { title: 'Last 30 days', value: '30d' },
  { title: 'Custom range…', value: 'custom' },
]

const providerOptions = [
  { title: 'Cloudflare (edge)', value: 'cloudflare' },
  { title: 'DataDome (bot)', value: 'datadome' },
  { title: 'F5 ASM (WAF)', value: 'f5asm' },
  { title: 'nginx (origin)', value: 'nginx' },
]

const outcomeOptions = [
  { title: 'Allowed', value: 'allowed' },
  // Kept distinct from Allowed: a layer in detection-only mode did not decide to
  // permit the request, and folding them together hides a layer that was never
  // enforcing at all.
  { title: 'Detected only', value: 'logged' },
  { title: 'Challenged', value: 'challenged' },
  { title: 'Rate limited', value: 'rate_limited' },
  { title: 'Blocked', value: 'blocked' },
]

const methodOptions = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

const qualityFlagOptions = [
  { title: 'Clock skew', value: 'clock_skew' },
  { title: 'Heuristic join', value: 'heuristic_correlation' },
  { title: 'Bridged join', value: 'bridged_correlation' },
  { title: 'Fields masked', value: 'fields_masked' },
  { title: 'Unmapped values', value: 'unmapped_values' },
  { title: 'No correlation key', value: 'no_correlation_key' },
  { title: 'DataDome fields absent', value: 'datadome_fields_absent' },
]

const activeCount = computed(() =>
  Object.entries(draft.value).filter(([k, v]) =>
    k !== 'limit' && v !== undefined && v !== null && v !== '' &&
    !(Array.isArray(v) && v.length === 0),
  ).length,
)

function apply() {
  emit('update:modelValue', { ...draft.value })
  emit('apply')
}

function clear() {
  draft.value = { limit: 50 }
  emit('update:modelValue', { limit: 50 })
  emit('apply')
}

/** Treats a blank numeric field as "no filter" rather than zero. */
function numberOrUndefined(value: string | number | null): number | undefined {
  const trimmed = String(value ?? '').trim()
  if (trimmed === '') return undefined
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center text-subtitle-1">
      Filters
      <v-chip v-if="activeCount" class="ml-2" size="x-small" color="primary" variant="tonal" data-test="active-filters">
        {{ activeCount }}
      </v-chip>
      <v-spacer />
      <v-btn variant="text" size="small" :disabled="!activeCount" @click="clear">Clear</v-btn>
    </v-card-title>

    <v-card-text>
      <v-form @submit.prevent="apply">
        <!--
          The one identifier that is definitive. Every layer that saw the request
          reports the same ray, so this is the fastest route from "one layer saw
          this" to "what did the others see" — and it does not depend on any
          clock agreeing with any other.
        -->
        <v-select
          v-model="draft.time_preset"
          :items="timeRangeOptions"
          label="Time range"
          density="compact"
          class="mb-1"
          data-test="time-range"
        />
        <template v-if="draft.time_preset === 'custom'">
          <!-- Native pickers: entered in the BROWSER's zone (the input shows
               its own zone-less local time), converted to UTC for the query. -->
          <v-text-field
            v-model="draft.from_local" type="datetime-local" label="From"
            density="compact" class="mb-1" data-test="time-from"
          />
          <v-text-field
            v-model="draft.to_local" type="datetime-local" label="To"
            density="compact" class="mb-2" hint="Empty = now" persistent-hint
            data-test="time-to"
          />
        </template>

        <v-text-field
          v-model="draft.ray_id"
          label="Ray ID"
          hint="Exact match across every layer that saw the request"
          persistent-hint clearable class="mb-3"
          prepend-inner-icon="mdi-identifier"
        />

        <!--
          The vendor's OWN reference, as opposed to the shared ray above. F5
          records the support_id an operator quotes to support and searches for
          in the ASM console — it is how an investigation that started there
          finds its way here.
        -->
        <v-text-field
          v-model="draft.support_id"
          label="Support ID (F5)"
          hint="F5's own reference for its record"
          persistent-hint clearable class="mb-3"
          prepend-inner-icon="mdi-lifebuoy"
        />

        <v-select
          v-model="draft.action" :items="outcomeOptions" label="Outcome"
          clearable class="mb-3" prepend-inner-icon="mdi-gavel"
        />

        <v-select
          v-model="draft.provider" :items="providerOptions" label="Provider"
          clearable class="mb-3" prepend-inner-icon="mdi-server"
        />

        <v-text-field
          v-model="draft.client_ip" label="Client IP"
          clearable class="mb-3" prepend-inner-icon="mdi-ip-network"
        />

        <v-text-field
          v-model="draft.host" label="Host"
          clearable class="mb-3" prepend-inner-icon="mdi-web"
        />

        <v-text-field
          v-model="draft.path_prefix" label="Path starts with"
          clearable class="mb-3" prepend-inner-icon="mdi-slash-forward"
        />

        <v-row dense class="mb-1">
          <v-col cols="7">
            <v-select v-model="draft.method" :items="methodOptions" label="Method" clearable />
          </v-col>
          <v-col cols="5">
            <v-text-field
              :model-value="draft.status" label="Status" type="number"
              @update:model-value="draft.status = numberOrUndefined($event)"
            />
          </v-col>
        </v-row>

        <v-text-field
          v-model="draft.rule_id" label="Rule ID"
          hint="The rule or signature that fired" persistent-hint
          clearable class="mb-3" prepend-inner-icon="mdi-script-text"
        />

        <v-text-field
          v-model="draft.user_agent" label="User agent contains"
          clearable class="mb-3" prepend-inner-icon="mdi-account-search"
        />

        <v-row dense class="mb-1">
          <v-col cols="6">
            <v-text-field v-model="draft.country" label="Country" clearable />
          </v-col>
          <v-col cols="6">
            <v-text-field
              :model-value="draft.asn" label="ASN" type="number"
              @update:model-value="draft.asn = numberOrUndefined($event)"
            />
          </v-col>
        </v-row>

        <v-divider class="my-3" />
        <div class="text-caption text-medium-emphasis mb-2">Correlation quality</div>

        <v-select
          v-model="draft.completeness" label="Completeness" clearable class="mb-3"
          :items="[
            { title: 'Complete — every layer reported', value: 'complete' },
            { title: 'Partial — a layer never reported', value: 'partial' },
            { title: 'Ambiguous — the join was not certain', value: 'ambiguous' },
          ]"
        />

        <v-select
          v-model="draft.correlation_method" label="Join tier" clearable class="mb-3"
          :items="[
            { title: 'Exact — shared identifier', value: 'exact' },
            { title: 'Heuristic — attributes and time', value: 'heuristic' },
          ]"
        />

        <!--
          Under-coverage is a collection question, not a security one. "Show me
          requests where the WAF never reported" is how a broken feed is found,
          and it needs asking directly rather than inferred from an empty result.
        -->
        <v-row dense class="mb-1">
          <v-col cols="6">
            <v-text-field
              :model-value="draft.min_layers" label="Min layers" type="number" min="1" max="4"
              @update:model-value="draft.min_layers = numberOrUndefined($event)"
            />
          </v-col>
          <v-col cols="6">
            <v-text-field
              :model-value="draft.max_layers" label="Max layers" type="number" min="1" max="4"
              @update:model-value="draft.max_layers = numberOrUndefined($event)"
            />
          </v-col>
        </v-row>

        <v-select
          v-model="draft.quality_flag" :items="qualityFlagOptions" label="Data quality"
          clearable class="mb-3" prepend-inner-icon="mdi-alert-outline"
        />

        <v-btn type="submit" color="primary" block prepend-icon="mdi-magnify" data-test="search">
          Search
        </v-btn>
      </v-form>
    </v-card-text>
  </v-card>
</template>
