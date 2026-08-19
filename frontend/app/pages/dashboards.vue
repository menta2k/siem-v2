<script setup lang="ts">
import { actionColor } from '~/plugins/vuetify'
const { identity, headers } = useApi()
const { can } = useAuth()
const config = useRuntimeConfig()

const stats = ref<any>(null)
const storage = ref<any>(null)
const loading = ref(false)
const error = ref('')

async function load() {
  loading.value = true; error.value = ''
  try {
    stats.value = await $fetch(`${config.public.apiBase}/stats/verdicts`, {
      headers: headers(),
    })
  } catch (e) {
    error.value = toDisplayMessage(e, 'Statistics could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(identity, load)

// Storage is fetched separately and its errors are swallowed (v1 behaviour):
// the panel says "unavailable" rather than degrading the whole dashboard.
async function loadStorage() {
  if (!can.value.manageRetention) return
  try {
    storage.value = await $fetch(`${config.public.apiBase}/stats/storage`, { headers: headers() })
  } catch {
    storage.value = null
  }
}
onMounted(loadStorage)
watch(() => can.value.manageRetention, loadStorage)

function blockRate(events: number, blocked: number) {
  return events > 0 ? `${Math.round((blocked / events) * 100)}%` : '—'
}

function bytes(n: number) {
  if (!n || n <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

// Threshold on DAYS, not percent (v1 rule): 40% full growing fast is worse
// than 90% full and steady.
const headroom = computed(() => {
  if (!storage.value) return null
  const st = storage.value
  if (st.steady) return { text: 'No growth measured', color: '' }
  const d = st.days_remaining
  if (d < 7) return { text: `${d.toFixed(1)} days`, color: 'text-error' }
  if (d < 30) return { text: `${Math.round(d)} days`, color: 'text-warning' }
  // Past a decade the exact figure is noise, not information.
  if (d > 3650) return { text: 'Over 10 years', color: 'text-success' }
  return { text: `${Math.round(d)} days`, color: 'text-success' }
})

const usedPercent = computed(() => {
  const hot = storage.value?.hot
  if (!hot?.reachable) return 0
  const total = hot.data_bytes + hot.free_bytes
  return total > 0 ? Math.min(100, Math.round((hot.data_bytes / total) * 100)) : 0
})

function pct(part: number, total: number) {
  return total > 0 ? Math.round((part / total) * 100) : 0
}
</script>

<template>
  <div>
    <CollectionHealthBanner />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate class="mb-3" />

    <template v-if="stats">
      <!--
        Correlation quality leads the page deliberately. Everything below it is
        only as trustworthy as the joins behind it, and a falling exact-join ratio
        means identifier propagation broke while flows still appear to form
        normally (FR-072e).
      -->
      <v-card class="mb-4" data-test="correlation-quality">
        <v-card-title class="text-subtitle-1">Correlation quality</v-card-title>
        <v-card-text>
          <div class="d-flex align-center ga-6 flex-wrap">
            <div>
              <div class="text-h4" :class="stats.exact_join_ratio >= 0.95 ? 'text-success' : 'text-warning'">
                {{ Math.round(stats.exact_join_ratio * 100) }}%
              </div>
              <div class="text-caption text-medium-emphasis">exact joins</div>
            </div>
            <div>
              <div class="text-h4">{{ stats.total_flows }}</div>
              <div class="text-caption text-medium-emphasis">flows</div>
            </div>
            <div>
              <div class="text-h4 text-info">{{ stats.bridged_flows }}</div>
              <div class="text-caption text-medium-emphasis">
                bridged
                <v-icon
icon="mdi-information-outline" size="x-small"
                  title="Joined through a record carrying two identifier spaces — these depend on the Cloudflare custom-field capture staying configured." />
              </div>
            </div>
          </div>
          <v-alert
            v-if="stats.exact_join_ratio < 0.95"
            type="warning" variant="tonal" density="compact" class="mt-3"
          >
            Exact-join rate is below target. Check that Logpush custom fields still capture
            <code>x-datadome-requestid</code>, nginx logs <code>$http_cf_ray</code>, and the F5 iRule is in place.
          </v-alert>
        </v-card-text>
      </v-card>

      <v-row dense>
        <v-col cols="12" md="4">
          <v-card>
            <v-card-title class="text-subtitle-2">Outcomes</v-card-title>
            <v-card-text>
              <div v-for="(n, k) in stats.by_outcome" :key="k" class="mb-2">
                <div class="d-flex justify-space-between text-caption">
                  <span>{{ k }}</span><span>{{ n }} ({{ pct(n, stats.total_flows) }}%)</span>
                </div>
                <v-progress-linear
:model-value="pct(n, stats.total_flows)"
                  :color="actionColor(String(k))" height="6" rounded />
              </div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" md="4">
          <v-card>
            <v-card-title class="text-subtitle-2">Terminating layer</v-card-title>
            <v-card-text>
              <div v-for="(n, k) in stats.by_terminating_layer" :key="k" class="d-flex justify-space-between text-caption mb-1">
                <span>{{ layerLabel(String(k)) }}</span><span>{{ n }}</span>
              </div>
              <div v-if="!Object.keys(stats.by_terminating_layer || {}).length" class="text-caption text-medium-emphasis">
                No request was terminated by a security layer.
              </div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" md="4">
          <v-card>
            <v-card-title class="text-subtitle-2">Completeness</v-card-title>
            <v-card-text>
              <div v-for="(n, k) in stats.by_completeness" :key="k" class="d-flex justify-space-between text-caption mb-1">
                <span>{{ k }}</span><span>{{ n }}</span>
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                A partial flow is one where a layer never reported — not one that was allowed.
              </div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" md="6">
          <v-card data-test="top-sources">
            <v-card-title class="text-subtitle-2">Top sources</v-card-title>
            <v-card-text>
              <v-table density="compact">
                <thead>
                  <tr><th>Client</th><th>Country</th><th class="text-right">Events</th><th class="text-right">Blocked</th></tr>
                </thead>
                <tbody>
                  <tr v-for="src in stats.top_sources" :key="src.client_ip">
                    <td><code class="text-caption">{{ src.client_ip }}</code></td>
                    <td class="text-caption">
                      {{ src.country || '—' }}
                      <div v-if="src.asn_owner" class="text-caption text-medium-emphasis">{{ src.asn_owner }}</div>
                    </td>
                    <td class="text-right text-caption">{{ src.events }}</td>
                    <td class="text-right text-caption">{{ blockRate(src.events, src.blocked) }}</td>
                  </tr>
                  <tr v-if="!stats.top_sources?.length">
                    <td colspan="4" class="text-caption text-medium-emphasis">No sources in this range.</td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" md="6">
          <v-card data-test="top-networks">
            <v-card-title class="text-subtitle-2">
              Top networks
              <span class="text-caption text-medium-emphasis ml-1">by origin ASN, where the vendor reports one</span>
            </v-card-title>
            <v-card-text>
              <v-table density="compact">
                <thead>
                  <tr><th>Network</th><th>Country</th><th class="text-right">Clients</th><th class="text-right">Events</th><th class="text-right">Blocked</th></tr>
                </thead>
                <tbody>
                  <tr v-for="net in stats.top_networks" :key="net.asn">
                    <td>
                      <NuxtLink :to="{ path: '/', query: { asn: net.asn } }" class="text-caption text-primary">AS{{ net.asn }}</NuxtLink>
                      <div v-if="net.owner && net.owner !== `AS${net.asn}`" class="text-caption text-medium-emphasis">{{ net.owner }}</div>
                    </td>
                    <td class="text-caption">{{ net.country || '—' }}</td>
                    <td class="text-right text-caption">{{ net.clients }}</td>
                    <td class="text-right text-caption">{{ net.events }}</td>
                    <td class="text-right text-caption">{{ blockRate(net.events, net.blocked) }}</td>
                  </tr>
                  <tr v-if="!stats.top_networks?.length">
                    <td colspan="5" class="text-caption text-medium-emphasis">
                      No network attribution in this range — no vendor reported an ASN.
                    </td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col v-if="can.manageRetention" cols="12">
          <v-card data-test="storage-headroom">
            <v-card-title class="text-subtitle-2">Storage headroom</v-card-title>
            <v-card-text>
              <template v-if="storage && headroom">
                <div class="text-h4" :class="headroom.color">
                  {{ headroom.text }}<span v-if="!storage.steady" class="text-body-2 text-medium-emphasis"> until full</span>
                </div>
                <v-progress-linear
                  :model-value="usedPercent" height="8" rounded class="my-3"
                  :color="headroom.color ? headroom.color.replace('text-', '') : 'primary'"
                />
                <div class="text-caption">
                  Hot tier: {{ bytes(storage.hot.data_bytes) }} used, {{ bytes(storage.hot.free_bytes) }} free.
                  <template v-if="storage.warm?.reachable">
                    Warm tier: {{ bytes(storage.warm.data_bytes) }} used, {{ bytes(storage.warm.free_bytes) }} free.
                  </template>
                  <template v-else>Warm tier unreachable.</template>
                </div>
                <div class="text-caption text-medium-emphasis">
                  <template v-if="storage.steady">No whole day of ingest has been measured yet.</template>
                  <template v-else>
                    Writing {{ bytes(storage.bytes_per_day) }} per day — averaged over
                    {{ storage.measured_days }} whole {{ storage.measured_days === 1 ? 'day' : 'days' }}.
                    A straight-line projection: retention expiry will slow real growth.
                  </template>
                </div>
              </template>
              <div v-else class="text-caption text-medium-emphasis">Storage figures are unavailable.</div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12">
          <v-card>
            <v-card-title class="text-subtitle-2">Records per provider</v-card-title>
            <v-card-text>
              <div v-for="(n, k) in stats.by_provider" :key="k" class="mb-2">
                <div class="d-flex justify-space-between text-caption">
                  <span>{{ k }}</span><span>{{ n }}</span>
                </div>
                <v-progress-linear
:model-value="pct(n, Math.max(...Object.values(stats.by_provider || {1:1}) as number[]))"
                  color="primary" height="6" rounded />
              </div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>
    </template>
  </div>
</template>
