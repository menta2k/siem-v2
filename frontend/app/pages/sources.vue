<script setup lang="ts">
const { identity, headers } = useApi()
const { can } = useAuth()
const config = useRuntimeConfig()

const PROVIDERS = ['cloudflare', 'datadome', 'f5asm', 'nginx']

const sources = ref<any[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')

// Onboarding is a gate, not a checklist (FR-008): the server refuses a source
// missing any of these, naming the quiet failure each absence would cause.
const createOpen = ref(false)
const busy = ref(false)
const draft = reactive({
  id: '',
  provider: 'nginx',
  delivery_mode: 'push',
  expected_cadence_seconds: 900,
  data_classification: 'standard',
  parser_version: '',
  detection_posture: 'pipeline.source_silence',
})

watch(() => draft.provider, (p) => {
  if (!draft.parser_version || PROVIDERS.some(v => draft.parser_version === `${v}/1.0`)) {
    draft.parser_version = `${p}/1.0`
  }
})
draft.parser_version = `${draft.provider}/1.0`

async function createSource() {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await $fetch(`${config.public.apiBase}/sources`, {
      method: 'POST', headers: headers(),
      body: {
        ...draft,
        id: draft.id.trim(),
        enabled: true,
        health_state: 'awaiting_first_record',
        credential_valid: true,
      },
    })
    createOpen.value = false
    notice.value = `Source ${draft.id.trim()} registered — it shows Awaiting first record until the first delivery arrives.`
    draft.id = ''
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The source could not be registered.')
  } finally {
    busy.value = false
  }
}

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/sources`, {
      headers: headers(),
    })
    sources.value = res.sources ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'Sources could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(identity, load)

function cadence(seconds: number) {
  if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`
  if (seconds >= 60) return `${Math.round(seconds / 60)}m`
  return `${seconds}s`
}
</script>

<template>
  <div>
    <CollectionHealthBanner />
    <v-alert v-if="error" type="error" variant="tonal" closable class="mb-3" @click:close="error = ''">{{ error }}</v-alert>
    <v-alert v-if="notice" type="success" variant="tonal" closable class="mb-3" @click:close="notice = ''">{{ notice }}</v-alert>
    <v-progress-linear v-if="loading || busy" indeterminate class="mb-3" />

    <v-card>
      <v-card-title class="d-flex align-center text-subtitle-1">
        Log sources
        <v-spacer />
        <v-btn
          v-if="can.manageSources" color="primary" size="small"
          data-test="new-source" @click="createOpen = true"
        >New source</v-btn>
      </v-card-title>
      <v-card-text>
        <v-table density="compact" data-test="sources">
          <thead>
            <tr>
              <th>Source</th><th>Provider</th><th>Delivery</th><th>Health</th>
              <th>Cadence</th><th>Classification</th><th>Parser</th><th>Detection posture</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in sources" :key="s.id">
              <td class="text-caption">{{ s.id }}</td>
              <td class="text-caption">{{ s.provider }}</td>
              <td>
                <v-chip
size="x-small" variant="outlined"
                  :title="s.delivery_mode === 'pull' ? 'We poll the provider on a schedule and track a watermark.' : 'The provider posts to our ingest endpoint.'">
                  {{ s.delivery_mode }}
                </v-chip>
              </td>
              <td>
                <SourceHealthChip
                  :enabled="s.enabled"
                  :health-state="s.health_state"
                  :credential-valid="s.credential_valid"
                  :schema-drift="s.schema_drift"
                  :last-record-at="s.last_record_at"
                />
              </td>
              <td class="text-caption">{{ cadence(s.expected_cadence_seconds) }}</td>
              <td>
                <v-chip
size="x-small" variant="text"
                  :color="s.data_classification === 'sensitive' ? 'warning' : undefined">
                  {{ s.data_classification }}
                </v-chip>
              </td>
              <td class="text-caption">{{ s.parser_version }}</td>
              <td class="text-caption text-medium-emphasis" style="max-width:320px">
                {{ s.detection_posture }}
              </td>
            </tr>
          </tbody>
        </v-table>

        <v-alert v-if="!loading && sources.length === 0" type="info" variant="tonal" density="compact" class="mt-3">
          No sources configured for this tenant.
        </v-alert>
      </v-card-text>
    </v-card>
    <v-dialog v-model="createOpen" max-width="560">
    <v-card class="pa-2">
      <v-card-title class="text-subtitle-1">Register a log source</v-card-title>
      <v-card-text>
        <v-text-field
          v-model="draft.id" label="Source ID" density="compact"
          hint="Stable identifier, e.g. cf-prod-1 — it appears in health alerts" persistent-hint
          data-test="source-id"
        />
        <div class="d-flex ga-3 mt-2">
          <v-select v-model="draft.provider" :items="PROVIDERS" label="Provider" density="compact" />
          <v-select v-model="draft.delivery_mode" :items="['push', 'pull']" label="Delivery" density="compact" />
        </div>
        <div class="d-flex ga-3">
          <v-text-field
            v-model.number="draft.expected_cadence_seconds" label="Expected cadence (seconds)"
            type="number" density="compact"
            hint="Without it, silence is undetectable" persistent-hint
          />
          <v-select
            v-model="draft.data_classification" :items="['standard', 'sensitive']"
            label="Data classification" density="compact"
            hint="Sensitive stores masked fields" persistent-hint
          />
        </div>
        <v-text-field v-model="draft.parser_version" label="Parser version" density="compact" class="mt-2" />
        <v-text-field
          v-model="draft.detection_posture" label="Detection posture" density="compact"
          hint="Which pipeline detections watch this source, or why none do" persistent-hint
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="createOpen = false">Cancel</v-btn>
        <v-btn
          color="primary" :disabled="busy || !draft.id.trim()"
          data-test="source-create" @click="createSource"
        >Register</v-btn>
      </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>