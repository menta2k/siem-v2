<script setup lang="ts">
/**
 * Traffic profiles: the learned baseline of every profiled endpoint — which
 * parameters each URL accepts, their types, and the structural ceilings of the
 * requests that reach it. /job/8584286 and /job/8584287 appear here as one
 * route, /job/{int}, with the ID profiled as a path parameter.
 */
import {
  ceiling, compact, methodColor, statusMixSlices, templateSegments,
  typeColor, typeComposition,
} from '~/lib/profiles'

const { identity, headers } = useApi()
const { can } = useAuth()
const { dateTime } = usePrefs()
const config = useRuntimeConfig()

interface HostStat {
  host: string
  endpoints: number
  observations: number
  last_seen: string
}
interface Endpoint {
  id: string
  host: string
  method: string
  path_template: string
  observations: number
  first_seen: string
  last_seen: string
  truncated: boolean
  param_count: number
  providers: string[]
  status_mix: Record<string, number> | null
  max_request_bytes: number | null
  max_header_count: number | null
  max_header_bytes: number | null
  max_cookie_count: number | null
  max_param_count: number | null
  max_value_len: number | null
  max_path_len: number | null
  cookie_names?: string[]
  cookie_names_count?: number
  params?: Param[]
}
interface Param {
  location: 'query' | 'path'
  name: string
  inferred_type: string
  observations: number
  present_count: number
  presence: number
  min_len: number
  max_len: number
  distinct_estimate: number
  enum_values: string[]
  enum_overflowed: boolean
  last_seen: string
}
interface ProfilerConfig {
  enabled: boolean
  hosts: string[]
  exclude_paths: string[]
  cookie_names: boolean
  min_observations_to_publish: number
}

const error = ref('')
const notice = ref('')

// ---- host strip -----------------------------------------------------------
const hosts = ref<HostStat[]>([])
async function loadHosts() {
  try {
    const res: any = await $fetch(`${config.public.apiBase}/profiles/hosts`, { headers: headers() })
    hosts.value = res.hosts ?? []
  } catch {
    hosts.value = [] // the strip is a garnish; the table carries its own error
  }
}

// ---- endpoint list --------------------------------------------------------
const endpoints = ref<Endpoint[]>([])
const total = ref(0)
const page = ref(1)
const perPage = 50
const loading = ref(false)
const hostFilter = ref('')
const methodFilter = ref('')
const search = ref('')
const showAll = ref(false)
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

async function loadList() {
  loading.value = true
  error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/profiles`, {
      headers: headers(),
      query: {
        host: hostFilter.value || undefined,
        method: methodFilter.value || undefined,
        q: search.value || undefined,
        all: showAll.value ? 'true' : undefined,
        page: page.value,
        per_page: perPage,
      },
    })
    endpoints.value = res.endpoints ?? []
    total.value = res.total ?? 0
  } catch (e) {
    error.value = toDisplayMessage(e, 'The traffic profiles could not be loaded.')
  } finally {
    loading.value = false
  }
}
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / perPage)))

function refresh() {
  loadHosts()
  loadList()
}
onMounted(refresh)
watch(identity, () => { page.value = 1; refresh() })
watch([hostFilter, methodFilter, showAll], () => { page.value = 1; loadList() })
watch(page, loadList)
let searchDebounce: ReturnType<typeof setTimeout> | undefined
watch(search, () => {
  clearTimeout(searchDebounce)
  searchDebounce = setTimeout(() => { page.value = 1; loadList() }, 350)
})

// ---- detail drawer --------------------------------------------------------
const drawer = ref(false)
const detail = ref<Endpoint | null>(null)
const detailLoading = ref(false)
async function openDetail(ep: Endpoint) {
  drawer.value = true
  detail.value = null
  detailLoading.value = true
  try {
    const res: any = await $fetch(`${config.public.apiBase}/profiles/${ep.id}`, { headers: headers() })
    detail.value = res.endpoint
  } catch (e) {
    error.value = toDisplayMessage(e, 'The endpoint profile could not be loaded.')
    drawer.value = false
  } finally {
    detailLoading.value = false
  }
}

const confirmForget = ref(false)
const forgetting = ref(false)
async function forgetEndpoint() {
  if (!detail.value) return
  forgetting.value = true
  try {
    await $fetch(`${config.public.apiBase}/profiles/${detail.value.id}`, {
      method: 'DELETE', headers: headers(),
    })
    notice.value = 'Profile forgotten. Live traffic will re-learn this endpoint.'
    confirmForget.value = false
    drawer.value = false
    refresh()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The profile could not be deleted.')
  } finally {
    forgetting.value = false
  }
}

/** The shape panel: measured ceilings and honest gaps, in one list. */
const shapeRows = computed(() => {
  const d = detail.value
  if (!d) return []
  return [
    { label: 'Max request size', value: ceiling(d.max_request_bytes, 'B'), captured: d.max_request_bytes != null },
    { label: 'Max headers', value: ceiling(d.max_header_count), captured: d.max_header_count != null },
    { label: 'Max header bytes', value: ceiling(d.max_header_bytes, 'B'), captured: d.max_header_bytes != null },
    { label: 'Max cookies', value: ceiling(d.max_cookie_count), captured: d.max_cookie_count != null },
    { label: 'Max query parameters', value: ceiling(d.max_param_count), captured: d.max_param_count != null },
    { label: 'Longest value', value: ceiling(d.max_value_len, ' chars'), captured: d.max_value_len != null },
    { label: 'Longest path', value: ceiling(d.max_path_len, ' chars'), captured: d.max_path_len != null },
  ]
})

// ---- configuration --------------------------------------------------------
const configDialog = ref(false)
const cfg = ref<ProfilerConfig>({
  enabled: false, hosts: [], exclude_paths: [], cookie_names: false, min_observations_to_publish: 20,
})
const cfgBusy = ref(false)
const cfgError = ref('')
async function openConfig() {
  cfgError.value = ''
  configDialog.value = true
  try {
    const res: any = await $fetch(`${config.public.apiBase}/profiler/config`, { headers: headers() })
    cfg.value = res.config
  } catch (e) {
    cfgError.value = toDisplayMessage(e, 'The configuration could not be loaded.')
  }
}
async function saveConfig() {
  cfgBusy.value = true
  cfgError.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/profiler/config`, {
      method: 'POST', headers: headers(), body: { config: cfg.value },
    })
    cfg.value = res.config
    configDialog.value = false
    notice.value = cfg.value.enabled && cfg.value.hosts.length
      ? `Profiling ${cfg.value.hosts.length} host pattern(s). Profiles appear as traffic arrives.`
      : 'Profiling is off. Existing profiles remain readable.'
  } catch (e) {
    cfgError.value = toDisplayMessage(e, 'The configuration could not be saved.')
  } finally {
    cfgBusy.value = false
  }
}
/** Observed hosts make the allow-list a pick, not a typing exercise. */
const hostSuggestions = computed(() => hosts.value.map(h => h.host))
</script>

<template>
  <div>
    <v-alert v-if="error" type="error" variant="tonal" closable class="mb-3" @click:close="error = ''">{{ error }}</v-alert>
    <v-alert v-if="notice" type="success" variant="tonal" closable class="mb-3" @click:close="notice = ''">{{ notice }}</v-alert>

    <!-- Host strip -->
    <v-row v-if="hosts.length" dense class="mb-2">
      <v-col v-for="h in hosts" :key="h.host" cols="12" sm="6" md="4" lg="3">
        <v-card
          variant="tonal" density="compact" class="cursor-pointer"
          :color="hostFilter === h.host ? 'primary' : undefined"
          data-test="host-card"
          @click="hostFilter = hostFilter === h.host ? '' : h.host"
        >
          <v-card-text class="py-2">
            <div class="text-subtitle-2 text-truncate">{{ h.host }}</div>
            <div class="text-caption text-medium-emphasis">
              {{ h.endpoints }} endpoint{{ h.endpoints === 1 ? '' : 's' }} ·
              {{ compact(h.observations) }} requests · last {{ dateTime(h.last_seen) }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-card>
      <v-card-title class="d-flex align-center flex-wrap text-subtitle-1" style="gap: 8px">
        Traffic profiles
        <v-spacer />
        <v-select
          v-model="methodFilter" :items="['', ...METHODS]" label="Method" density="compact"
          hide-details variant="outlined" style="max-width: 130px" clearable
        />
        <v-text-field
          v-model="search" label="Search path" density="compact" hide-details
          variant="outlined" prepend-inner-icon="mdi-magnify" style="max-width: 220px" clearable
          data-test="profile-search"
        />
        <v-switch
          v-model="showAll" label="Show rare" density="compact" hide-details color="primary"
        />
        <v-btn icon="mdi-refresh" size="small" variant="text" :loading="loading" @click="refresh" />
        <v-btn
          v-if="can.manageSources" size="small" variant="outlined"
          prepend-icon="mdi-cog-outline" data-test="configure-profiler" @click="openConfig"
        >Configure</v-btn>
      </v-card-title>

      <v-progress-linear v-if="loading" indeterminate />

      <v-card-text v-if="!loading && !endpoints.length" class="text-medium-emphasis">
        No profiles yet. Enable profiling and pick the hosts to analyze under
        <em>Configure</em> — profiles build up as traffic arrives.
      </v-card-text>

      <v-table v-else density="comfortable" data-test="profiles-table">
        <thead>
          <tr>
            <th style="width: 90px">Method</th>
            <th>Route</th>
            <th class="text-right">Requests</th>
            <th class="text-right">Params</th>
            <th style="width: 120px">Status mix</th>
            <th>Last seen</th>
            <th style="width: 40px" />
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="ep in endpoints" :key="ep.id" class="cursor-pointer"
            data-test="profile-row" @click="openDetail(ep)"
          >
            <td>
              <v-chip size="small" :color="methodColor(ep.method)" variant="tonal" label>{{ ep.method }}</v-chip>
            </td>
            <td>
              <span class="text-caption text-medium-emphasis">{{ ep.host }}</span>
              <div class="route">
                <template v-for="(seg, i) in templateSegments(ep.path_template)" :key="i">
                  <span class="text-medium-emphasis">/</span><span :class="seg.isParam ? 'param-seg' : ''">{{ seg.text }}</span>
                </template>
              </div>
            </td>
            <td class="text-right">{{ compact(ep.observations) }}</td>
            <td class="text-right">{{ ep.param_count }}</td>
            <td>
              <svg v-if="statusMixSlices(ep.status_mix).length" width="100" height="8" class="mix-bar">
                <template v-for="(s, i) in statusMixSlices(ep.status_mix)" :key="s.cls">
                  <rect
                    :x="100 * statusMixSlices(ep.status_mix).slice(0, i).reduce((a, p) => a + p.share, 0)"
                    y="0" :width="Math.max(1, 100 * s.share)" height="8" :fill="s.color" rx="1"
                  >
                    <title>{{ s.cls }}: {{ s.count }}</title>
                  </rect>
                </template>
              </svg>
              <span v-else class="text-caption text-medium-emphasis">—</span>
            </td>
            <td class="text-caption">{{ dateTime(ep.last_seen) }}</td>
            <td>
              <v-tooltip v-if="ep.truncated" text="A learning cap was hit; this profile is incomplete.">
                <template #activator="{ props }">
                  <v-icon v-bind="props" size="small" color="warning">mdi-alert-circle-outline</v-icon>
                </template>
              </v-tooltip>
            </td>
          </tr>
        </tbody>
      </v-table>

      <v-card-actions v-if="pageCount > 1">
        <v-spacer />
        <v-pagination v-model="page" :length="pageCount" density="compact" total-visible="7" />
        <v-spacer />
      </v-card-actions>
    </v-card>

    <!-- Endpoint detail drawer -->
    <v-navigation-drawer v-model="drawer" location="right" temporary :width="760">
      <v-progress-linear v-if="detailLoading" indeterminate />
      <template v-if="detail">
        <v-toolbar density="compact" color="transparent">
          <v-chip size="small" :color="methodColor(detail.method)" variant="tonal" label class="ml-3">
            {{ detail.method }}
          </v-chip>
          <v-toolbar-title class="text-subtitle-2">
            {{ detail.host }}{{ detail.path_template }}
          </v-toolbar-title>
          <v-btn
            v-if="can.manageSources" size="small" variant="text" color="error"
            prepend-icon="mdi-delete-outline" data-test="forget-profile" @click="confirmForget = true"
          >Forget</v-btn>
          <v-btn icon="mdi-close" size="small" variant="text" @click="drawer = false" />
        </v-toolbar>

        <v-container fluid class="pt-0">
          <v-alert v-if="detail.truncated" type="warning" variant="tonal" density="compact" class="mb-3">
            A learning cap was hit for this endpoint — the profile is incomplete, not exhaustive.
          </v-alert>

          <v-row dense>
            <v-col cols="6" sm="3">
              <div class="text-caption text-medium-emphasis">Requests</div>
              <div class="text-h6">{{ compact(detail.observations) }}</div>
            </v-col>
            <v-col cols="6" sm="3">
              <div class="text-caption text-medium-emphasis">Parameters</div>
              <div class="text-h6">{{ detail.param_count }}</div>
            </v-col>
            <v-col cols="6" sm="3">
              <div class="text-caption text-medium-emphasis">First seen</div>
              <div class="text-body-2">{{ dateTime(detail.first_seen) }}</div>
            </v-col>
            <v-col cols="6" sm="3">
              <div class="text-caption text-medium-emphasis">Last seen</div>
              <div class="text-body-2">{{ dateTime(detail.last_seen) }}</div>
            </v-col>
          </v-row>

          <!-- Type composition -->
          <template v-if="detail.params?.length">
            <div class="text-caption text-medium-emphasis mt-3 mb-1">Parameter types</div>
            <svg width="100%" height="14" viewBox="0 0 100 14" preserveAspectRatio="none" class="mix-bar">
              <template v-for="(s, i) in typeComposition(detail.params)" :key="s.cls">
                <rect
                  :x="100 * typeComposition(detail.params).slice(0, i).reduce((a, p) => a + p.share, 0)"
                  y="0" :width="100 * s.share" height="14"
                  :class="`type-fill-${s.cls}`"
                >
                  <title>{{ s.cls }}: {{ s.count }}</title>
                </rect>
              </template>
            </svg>
            <div class="d-flex flex-wrap mt-1" style="gap: 4px">
              <v-chip
                v-for="s in typeComposition(detail.params)" :key="s.cls"
                size="x-small" :color="typeColor(s.cls)" variant="tonal" label
              >{{ s.cls }} × {{ s.count }}</v-chip>
            </div>
          </template>

          <!-- Shape panel -->
          <div class="text-caption text-medium-emphasis mt-4 mb-1">Request shape ceilings</div>
          <v-table density="compact" class="shape-table">
            <tbody>
              <tr v-for="row in shapeRows" :key="row.label">
                <td class="text-medium-emphasis" style="width: 220px">{{ row.label }}</td>
                <td>
                  <template v-if="row.captured">{{ row.value }}</template>
                  <v-tooltip v-else text="No provider for this host ships this fact yet. It is absent, not zero.">
                    <template #activator="{ props }">
                      <v-chip v-bind="props" size="x-small" variant="tonal" color="grey">not captured</v-chip>
                    </template>
                  </v-tooltip>
                </td>
              </tr>
              <tr v-if="detail.cookie_names?.length">
                <td class="text-medium-emphasis">Cookie names</td>
                <td>
                  <v-chip v-for="c in detail.cookie_names" :key="c" size="x-small" class="mr-1" variant="tonal">{{ c }}</v-chip>
                </td>
              </tr>
              <tr>
                <td class="text-medium-emphasis">Providers</td>
                <td class="text-caption">{{ detail.providers?.join(', ') || '—' }}</td>
              </tr>
            </tbody>
          </v-table>

          <!-- Parameters -->
          <div class="text-caption text-medium-emphasis mt-4 mb-1">Parameters</div>
          <v-table v-if="detail.params?.length" density="compact" data-test="params-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Where</th>
                <th>Type</th>
                <th style="min-width: 140px">Presence</th>
                <th class="text-right">Length</th>
                <th class="text-right">Distinct</th>
                <th>Values</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="p in detail.params" :key="`${p.location}-${p.name}`">
                <td class="font-weight-medium">{{ p.name }}</td>
                <td><v-chip size="x-small" variant="tonal" :color="p.location === 'path' ? 'brown' : 'primary'">{{ p.location }}</v-chip></td>
                <td><v-chip size="x-small" variant="tonal" :color="typeColor(p.inferred_type)" label>{{ p.inferred_type }}</v-chip></td>
                <td>
                  <v-progress-linear
                    :model-value="p.presence * 100" height="14" rounded
                    :color="p.presence > 0.95 ? 'success' : p.presence > 0.5 ? 'primary' : 'grey'"
                  >
                    <span class="text-caption">{{ Math.round(p.presence * 100) }}%</span>
                  </v-progress-linear>
                </td>
                <td class="text-right text-caption">
                  {{ p.min_len === p.max_len ? p.max_len : `${p.min_len}–${p.max_len}` }}
                </td>
                <td class="text-right text-caption">
                  {{ p.distinct_estimate }}{{ p.enum_overflowed ? '+' : '' }}
                </td>
                <td>
                  <template v-if="p.enum_values?.length && !p.enum_overflowed">
                    <v-chip
                      v-for="v in p.enum_values.slice(0, 6)" :key="v"
                      size="x-small" class="mr-1 mb-1" variant="outlined"
                    >{{ v.length > 24 ? `${v.slice(0, 24)}…` : v }}</v-chip>
                    <span v-if="p.enum_values.length > 6" class="text-caption text-medium-emphasis">
                      +{{ p.enum_values.length - 6 }} more
                    </span>
                  </template>
                  <span v-else class="text-caption text-medium-emphasis">
                    {{ p.enum_overflowed ? 'high cardinality' : '—' }}
                  </span>
                </td>
              </tr>
            </tbody>
          </v-table>
          <div v-else class="text-caption text-medium-emphasis">No parameters observed.</div>
        </v-container>
      </template>
    </v-navigation-drawer>

    <!-- Forget confirmation -->
    <v-dialog v-model="confirmForget" max-width="440">
      <v-card>
        <v-card-title class="text-subtitle-1">Forget this profile?</v-card-title>
        <v-card-text class="text-body-2">
          The learned baseline for this endpoint is deleted. If the endpoint still
          receives traffic it will be re-learned from scratch. The action is audited.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="confirmForget = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" :loading="forgetting" @click="forgetEndpoint">Forget</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Configuration dialog -->
    <v-dialog v-model="configDialog" max-width="640">
      <v-card>
        <v-card-title class="text-subtitle-1">Traffic profiler configuration</v-card-title>
        <v-card-text>
          <v-alert v-if="cfgError" type="error" variant="tonal" density="compact" class="mb-3">{{ cfgError }}</v-alert>
          <v-switch v-model="cfg.enabled" label="Profiling enabled" color="primary" hide-details class="mb-2" />
          <v-alert v-if="cfg.enabled && !cfg.hosts.length" type="info" variant="tonal" density="compact" class="mb-3">
            The host list is an explicit allow-list: with no hosts, nothing is profiled.
          </v-alert>
          <v-combobox
            v-model="cfg.hosts" :items="hostSuggestions" label="Hosts to analyze"
            multiple chips closable-chips clearable
            hint="Exact names or a single leading wildcard: *.shop.example.com" persistent-hint
            class="mb-3" data-test="config-hosts"
          />
          <v-combobox
            v-model="cfg.exclude_paths" label="Excluded path prefixes"
            multiple chips closable-chips clearable
            hint="Requests under these prefixes are ignored, e.g. /health" persistent-hint
            class="mb-3"
          />
          <v-text-field
            v-model.number="cfg.min_observations_to_publish" type="number" min="0"
            label="Hide endpoints with fewer requests than" density="compact"
            hint="One-off scanner URLs stay hidden until they recur; they are still counted." persistent-hint
            class="mb-3"
          />
          <v-switch
            v-model="cfg.cookie_names" color="primary" hide-details
            label="Record cookie names (not values)"
          />
          <div class="text-caption text-medium-emphasis">
            Cookie names can identify software in use; they are shown only to
            principals with sensitive-data permission. Values are never stored.
            Requires cookie capture on the feed — see the vendor connection guide.
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="configDialog = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" :loading="cfgBusy" data-test="save-config" @click="saveConfig">Save</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<style scoped>
.cursor-pointer { cursor: pointer; }
.route { font-family: monospace; font-size: 0.85rem; }
.param-seg {
  color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.08);
  border-radius: 4px;
  padding: 0 3px;
  font-weight: 600;
}
.mix-bar { display: block; border-radius: 2px; overflow: hidden; }
.shape-table td { height: 32px !important; }
/* Type composition fills mirror the chip colors (Vuetify palette anchors). */
.type-fill-int, .type-fill-float { fill: #009688; }
.type-fill-bool { fill: #4caf50; }
.type-fill-uuid { fill: #3f51b5; }
.type-fill-hex { fill: #673ab7; }
.type-fill-date { fill: #00bcd4; }
.type-fill-email { fill: #ff9800; }
.type-fill-ipv4, .type-fill-ipv6 { fill: #2196f3; }
.type-fill-json { fill: #9c27b0; }
.type-fill-alnum { fill: #607d8b; }
.type-fill-var { fill: #795548; }
.type-fill-freetext, .type-fill-empty { fill: #9e9e9e; }
</style>
