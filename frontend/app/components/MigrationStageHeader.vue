<script setup lang="ts">
import { WAF_RANGES } from '~/lib/wafMigration'

/**
 * The band atop each migration stage: which step, what it means in plain words,
 * what to do with a row — plus the range + host controls. Presentational; it
 * emits changes and the page owns the reload.
 */
defineProps<{
  step: number
  title: string
  definition: string
  action: string
  hours: number
  host: string
  loading?: boolean
}>()
const emit = defineEmits<{
  (e: 'update:hours', v: number): void
  (e: 'update:host', v: string): void
  (e: 'apply'): void
}>()
</script>

<template>
  <v-card class="mb-4" variant="tonal">
    <v-card-text>
      <div class="d-flex align-center flex-wrap ga-3">
        <div class="flex-grow-1" style="min-width:280px">
          <div class="text-overline text-medium-emphasis">Step {{ step }} of 3</div>
          <div class="text-h6">{{ title }}</div>
          <div class="text-body-2 text-medium-emphasis">{{ definition }}</div>
          <div class="text-caption mt-1"><v-icon icon="mdi-arrow-right-thin" size="x-small" /> {{ action }}</div>
        </div>
        <v-select
          :model-value="hours" :items="WAF_RANGES" item-title="title" item-value="hours"
          label="Range" density="compact" hide-details style="max-width:170px"
          @update:model-value="emit('update:hours', $event)"
        />
        <v-text-field
          :model-value="host" label="Host (optional)" density="compact" hide-details clearable
          style="max-width:220px" placeholder="all hosts"
          @update:model-value="emit('update:host', $event ?? '')"
          @keyup.enter="emit('apply')"
        />
        <v-btn color="primary" variant="flat" :loading="loading" prepend-icon="mdi-refresh" @click="emit('apply')">Apply</v-btn>
      </div>
    </v-card-text>
  </v-card>
</template>
