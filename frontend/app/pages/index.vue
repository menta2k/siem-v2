<script setup lang="ts">
import type { Flow, FlowSearch } from '~/composables/useApi'

const { searchFlows, identity } = useApi()
const flows = ref<Flow[]>([])
const loading = ref(false)
const error = ref('')
const filters = ref<FlowSearch>({ limit: 50 })

// Pagination: pages are meaningful because the server orders newest-first
// before slicing. A new search (filters applied) always restarts at page 0.
const PAGE_SIZE = 50
const page = ref(0)
const hasMore = ref(false)

// The dashboard's Top networks rows link here as /?asn=N — pre-apply it so
// the link lands on the filtered result, not on an empty form.
const route = useRoute()
const asnParam = Number(route.query.asn)
if (Number.isFinite(asnParam) && asnParam > 0) filters.value.asn = asnParam

// The drawer keeps the result set underneath, so working a list stays a list.
const { flowId: selectedFlowId, show: openFlow } = useFlowDrawer()
const { dateTime } = usePrefs()

async function run(resetPage = true) {
  if (resetPage) page.value = 0
  loading.value = true
  error.value = ''
  try {
    const res = await searchFlows({
      ...filters.value, limit: PAGE_SIZE, offset: page.value * PAGE_SIZE,
    })
    flows.value = res.flows ?? []
    // A full page means there is PROBABLY more; the last page shows shorter.
    hasMore.value = flows.value.length === PAGE_SIZE
  } catch (e) {
    error.value = toDisplayMessage(e, 'The search could not be completed.')
    flows.value = []
    hasMore.value = false
  } finally {
    loading.value = false
  }
}

function goto(delta: number) {
  page.value = Math.max(0, page.value + delta)
  run(false)
}

// Rendered in the USER'S chosen zone (usePrefs); the stored instant is UTC.
const eventTime = (iso: string | undefined) => dateTime(iso)

onMounted(() => run())
watch(identity, () => run())
</script>

<template>
  <div>
    <CollectionHealthBanner />

    <v-row>
      <v-col cols="12" md="3">
        <SearchFilters v-model="filters" @apply="run" />
      </v-col>

      <v-col cols="12" md="9">
        <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
        <v-progress-linear v-if="loading" indeterminate color="primary" class="mb-3" />

        <v-alert
          v-if="!loading && !error && flows.length === 0"
          type="info" variant="tonal" data-test="empty"
        >
          No request flows match these filters for the signed-in tenant.
        </v-alert>

        <v-card v-if="flows.length">
          <v-card-text class="d-flex align-center py-2 text-caption text-medium-emphasis">
            <span data-test="count">
              {{ flows.length }} flow(s) — page {{ page + 1 }}
            </span>
            <v-spacer />
            <v-btn
              size="small" variant="text" prepend-icon="mdi-chevron-left"
              :disabled="loading || page === 0" data-test="prev-page" @click="goto(-1)"
            >Prev</v-btn>
            <v-btn
              size="small" variant="text" append-icon="mdi-chevron-right"
              :disabled="loading || !hasMore" data-test="next-page" @click="goto(1)"
            >Next</v-btn>
            <v-btn size="small" variant="text" prepend-icon="mdi-refresh" :loading="loading" @click="run(false)">
              Refresh
            </v-btn>
          </v-card-text>
          <v-divider />

          <v-table data-test="results">
            <thead>
              <tr>
                <th>Time</th><th>Outcome</th><th>Terminated at</th><th>Host</th><th>Path</th>
                <th>Client</th><th>Layers</th><th>Join</th><th>Quality</th><th/>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="f in flows" :key="f.flow_id" style="cursor:pointer"
                :class="{ 'bg-surface-bright': f.flow_id === selectedFlowId }"
                @click="openFlow(f.flow_id)"
              >
                <td class="text-caption text-no-wrap" :title="'first event ' + eventTime(f.first_seen)">{{ eventTime(f.last_seen) }}</td>
                <td><VerdictBadge :action="f.effective_outcome" /></td>
                <td class="text-caption">
                  <span v-if="f.terminating_layer">{{ layerLabel(f.terminating_layer) }}</span>
                  <span v-else class="text-medium-emphasis">—</span>
                </td>
                <td class="text-caption">{{ f.request?.host }}</td>
                <td class="text-caption text-truncate" style="max-width:240px">{{ f.request?.path }}</td>
                <td class="text-caption">{{ f.client?.ip }}</td>
                <td>
                  <v-chip
                    size="x-small" variant="tonal"
                    :color="f.completeness === 'complete' ? 'success' : 'warning'"
                    :title="f.layers_missing?.length ? `Missing: ${f.layers_missing.join(', ')}` : 'All expected layers reported'"
                  >
                    {{ f.layers_present?.length ?? 0 }}/4
                  </v-chip>
                </td>
                <td>
                  <ConfidenceChip
                    :method="f.correlation_method" :confidence="f.correlation_confidence"
                    :bridged="f.bridged" :completeness="f.completeness"
                  />
                </td>
                <td>
                  <v-chip
                    v-if="f.data_quality_flags?.length" size="x-small" color="warning" variant="text"
                    :title="f.data_quality_flags.join(', ')"
                  >
                    <v-icon icon="mdi-alert-outline" start size="x-small" />
                    {{ f.data_quality_flags.length }}
                  </v-chip>
                </td>
                <td><v-icon icon="mdi-chevron-right" size="small" class="text-medium-emphasis" /></td>
              </tr>
            </tbody>
          </v-table>
        </v-card>
      </v-col>
    </v-row>

  </div>
</template>
