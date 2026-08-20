<script setup lang="ts">
// System settings. First panel: how long raw provider evidence is kept.
// Raw records live in their own retention class (a dedicated store), so this
// window is independent of flow retention — shortening it here reclaims the
// evidence store without touching correlated flows.
const { headers } = useApi()
const config = useRuntimeConfig()

const days = ref<number | null>(null)
const minDays = ref(1)
const maxDays = ref(365)
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/settings/raw-retention`, { headers: headers() })
    days.value = res.days
    minDays.value = res.min_days ?? 1
    maxDays.value = res.max_days ?? 365
  } catch (e) {
    error.value = toDisplayMessage(e, 'The retention setting could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)

const invalid = computed(() =>
  days.value === null || days.value < minDays.value || days.value > maxDays.value)

async function save() {
  if (invalid.value) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await $fetch(`${config.public.apiBase}/settings/raw-retention`, {
      method: 'POST', headers: headers(), body: { days: days.value },
    })
    notice.value = 'Raw evidence retention updated.'
  } catch (e) {
    error.value = toDisplayMessage(e, 'The retention window could not be saved.')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-container class="py-6" style="max-width: 760px">
    <h1 class="text-h5 mb-1">Settings</h1>
    <p class="text-body-2 text-medium-emphasis mb-4">
      System-wide configuration.
    </p>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>
    <v-alert v-if="notice" type="success" variant="tonal" class="mb-4">{{ notice }}</v-alert>

    <v-card :loading="loading">
      <v-card-title class="text-subtitle-1">Raw evidence retention</v-card-title>
      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-4">
          The unmodified records collected from each provider are kept as evidence
          in a dedicated store with its own retention. Records older than this
          window are deleted on the next hourly retention pass.
        </p>
        <v-text-field
          v-model.number="days"
          type="number"
          label="Retention window (days)"
          :min="minDays" :max="maxDays"
          :hint="`Between ${minDays} and ${maxDays} days`"
          persistent-hint
          :disabled="loading || busy"
          data-test="raw-retention-days"
          style="max-width: 240px"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn
          color="primary" variant="flat"
          :loading="busy" :disabled="invalid || loading"
          data-test="raw-retention-save"
          @click="save"
        >Save</v-btn>
      </v-card-actions>
    </v-card>
  </v-container>
</template>
