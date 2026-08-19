<script setup lang="ts">
const { identity, headers } = useApi()
const config = useRuntimeConfig()

const sources = ref<any[]>([])
const loading = ref(false)
const error = ref('')

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
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate class="mb-3" />

    <v-card>
      <v-card-title class="text-subtitle-1">Log sources</v-card-title>
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
  </div>
</template>
