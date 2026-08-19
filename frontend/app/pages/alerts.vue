<script setup lang="ts">
const { identity, headers } = useApi()
const config = useRuntimeConfig()

const alerts = ref<any[]>([])
const loading = ref(false)
const error = ref('')
// Default to open alerts: an on-call responder opening this page wants what
// still needs action, not a history.
const onlyOpen = ref(true)

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(
      `${config.public.apiBase}/alerts${onlyOpen.value ? '?acknowledged=false' : ''}`,
      { headers: headers() },
    )
    alerts.value = res.alerts ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'Alerts could not be loaded.')
  } finally {
    loading.value = false
  }
}

async function acknowledge(alertId: string) {
  try {
    await $fetch(`${config.public.apiBase}/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
      method: 'POST', headers: headers(),
    })
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The alert could not be acknowledged.')
  }
}

onMounted(load)
watch([identity, onlyOpen], load)

// Severity uses the same palette as verdicts, so "red means act now" is one
// lesson rather than two.
function severityColor(s: string) {
  return ({ critical: 'error', high: 'error', medium: 'warning', low: 'info' } as Record<string, string>)[s] ?? 'secondary'
}

function severityIcon(s: string) {
  return ({ critical: 'mdi-alert-octagon', high: 'mdi-alert', medium: 'mdi-alert-outline', low: 'mdi-information-outline' } as Record<string, string>)[s] ?? 'mdi-bell'
}
</script>

<template>
  <div>
    <CollectionHealthBanner />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>

    <v-card class="mb-3">
      <v-card-text class="d-flex align-center ga-3">
        <v-switch v-model="onlyOpen" label="Unacknowledged only" density="compact" hide-details color="primary" />
        <v-spacer />
        <v-btn size="small" variant="text" :loading="loading" @click="load">Refresh</v-btn>
      </v-card-text>
    </v-card>

    <v-progress-linear v-if="loading" indeterminate class="mb-3" />

    <v-alert v-if="!loading && alerts.length === 0" type="success" variant="tonal" data-test="no-alerts">
      No {{ onlyOpen ? 'unacknowledged ' : '' }}alerts. Note that this is only meaningful if collection
      is healthy — a silent pipeline also produces no alerts.
    </v-alert>

    <v-card v-for="a in alerts" :key="a.alert_id" class="mb-3" data-test="alert">
      <v-card-text>
        <div class="d-flex align-center ga-2 mb-2">
          <v-chip :color="severityColor(a.severity)" size="small" variant="tonal" label>
            <v-icon :icon="severityIcon(a.severity)" start size="x-small" />
            {{ a.severity }}
          </v-chip>
          <strong>{{ a.title }}</strong>
          <v-chip size="x-small" variant="text">{{ a.detection_id }} v{{ a.detection_version }}</v-chip>
          <v-chip
v-if="a.occurrence_count > 1" size="x-small" color="warning" variant="outlined"
            title="The condition recurred while suppressed; this is how many times.">
            ×{{ a.occurrence_count }}
          </v-chip>
          <v-spacer />
          <span class="text-caption">{{ new Date(a.fired_at).toISOString().replace('T', ' ').slice(0, 19) }}</span>
        </div>

        <!--
          Evidence is on the alert itself, not a link to go and find it. An alert
          that requires a separate query before anyone can act on it is an alert
          people learn to skip.
        -->
        <v-table v-if="a.evidence && Object.keys(a.evidence).length" density="compact" class="mb-2">
          <tbody>
            <tr v-for="(v, k) in a.evidence" :key="k">
              <td class="text-caption text-medium-emphasis" style="width:220px">{{ k }}</td>
              <td class="text-caption">{{ v }}</td>
            </tr>
          </tbody>
        </v-table>

        <div v-if="a.linked_flow_ids?.length" class="mb-2">
          <span class="text-caption text-medium-emphasis">Linked flows: </span>
          <v-chip
            v-for="id in a.linked_flow_ids" :key="id"
            size="x-small" variant="outlined" class="mr-1"
            :to="`/flows/${encodeURIComponent(id)}`"
          >{{ id }}</v-chip>
        </div>

        <div class="d-flex align-center ga-2">
          <v-chip
v-if="a.delivery_state === 'failed'" color="error" size="x-small" variant="flat"
            title="This alert could not be delivered to a configured destination.">
            delivery failed
          </v-chip>
          <v-chip v-else size="x-small" color="success" variant="tonal">{{ a.delivery_state }}</v-chip>
          <v-spacer />
          <v-btn v-if="!a.acknowledged_at" size="small" variant="tonal" @click="acknowledge(a.alert_id)">
            Acknowledge
          </v-btn>
          <span v-else class="text-caption">acknowledged by {{ a.acknowledged_by }}</span>
        </div>
      </v-card-text>
    </v-card>
  </div>
</template>
