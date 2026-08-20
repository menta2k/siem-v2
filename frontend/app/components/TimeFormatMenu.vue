<script setup lang="ts">
// The app-bar clock menu (ported from v1): pick a timezone and hour format,
// see a live preview, changes apply instantly. Display-only — see usePrefs.
import { COMMON_TIME_ZONES } from '~/lib/datetime'

const prefs = usePrefs()

const items = computed(() => [
  { title: `Browser (${prefs.browserZone.value})`, value: '' },
  ...COMMON_TIME_ZONES.map(z => ({ title: z, value: z })),
])

// A ticking preview: "Now shows as" must move, or a wrong zone looks right.
const now = ref(new Date())
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { timer = setInterval(() => { now.value = new Date() }, 1000) })
onUnmounted(() => { if (timer) clearInterval(timer) })
const preview = computed(() => prefs.dateTime(now.value))
</script>

<template>
  <v-menu :close-on-content-click="false">
    <template #activator="{ props }">
      <v-btn v-bind="props" variant="text" size="small" prepend-icon="mdi-clock-outline" data-test="time-format-menu">
        {{ prefs.activeTimeZone.value }}
      </v-btn>
    </template>
    <v-card min-width="300" class="pa-3">
      <v-select
        :model-value="prefs.format.value.timeZone" :items="items" label="Timezone"
        density="compact" variant="outlined" hide-details class="mb-3"
        data-test="tz-select"
        @update:model-value="(z: string) => prefs.setTimeZone(z)"
      />
      <v-btn-toggle
        :model-value="prefs.format.value.hourFormat" mandatory density="compact"
        class="mb-3" divided
        @update:model-value="(h: 'auto' | '12' | '24') => prefs.setHourFormat(h)"
      >
        <v-btn value="auto" size="small">Locale</v-btn>
        <v-btn value="24" size="small">24-hour</v-btn>
        <v-btn value="12" size="small">12-hour</v-btn>
      </v-btn-toggle>
      <div class="text-caption text-medium-emphasis">Now shows as</div>
      <div class="text-body-2 mb-2" data-test="tz-preview">{{ preview }}</div>
      <v-btn
        v-if="!prefs.followsBrowser.value || prefs.format.value.hourFormat !== 'auto'"
        size="small" variant="text" @click="prefs.reset()"
      >Use browser default</v-btn>
    </v-card>
  </v-menu>
</template>
