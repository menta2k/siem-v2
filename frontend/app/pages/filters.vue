<script setup lang="ts">
// Ingest filters (ported from v1's Admin tab): rules that stop matching
// records from being ingested AT ALL. Structured rows, not a textarea — every
// rule reads back as a sentence, and the foot is hard to shoot.
const { headers } = useApi()
const { can } = useAuth()
const config = useRuntimeConfig()

interface Rule { field: string, op: string, values: string[] }

const FIELDS = [
  { title: 'URL host', value: 'request_host' },
  { title: 'URL path', value: 'request_path' },
]
const OPS = [
  { title: 'equals', value: 'equals' },
  { title: 'starts with', value: 'prefix' },
  { title: 'ends with', value: 'suffix' },
  { title: 'contains', value: 'contains' },
]
const MAX_RULES = 64

const rules = ref<Rule[]>([])
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/filters`, { headers: headers() })
    rules.value = res.rules ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'The filters could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)

function addRule() {
  rules.value.push({ field: 'request_path', op: 'prefix', values: [] })
}
function removeRule(i: number) {
  rules.value.splice(i, 1)
}

/** Strip half-finished rows so a stray empty rule never blocks saving. */
function cleanRules(): Rule[] {
  return rules.value
    .map(r => ({ ...r, values: r.values.map(v => v.trim()).filter(Boolean) }))
    .filter(r => r.values.length > 0)
}

function describeRule(r: Rule): string {
  const subject = r.field === 'request_host' ? 'the host' : 'the URL path'
  const verb = { equals: 'equals', prefix: 'starts with', suffix: 'ends with', contains: 'contains' }[r.op]
  const vals = r.values.filter(Boolean)
  if (!vals.length) return 'Incomplete rule — add at least one value.'
  return `Drop events where ${subject} ${verb} ${vals.map(v => `"${v}"`).join(' or ')}.`
}

/** v1's guard: patterns that match nearly everything deserve a red flag. */
const overlyBroad = computed(() => cleanRules().some(r =>
  (r.op === 'prefix' && r.field === 'request_path' && r.values.includes('/'))
  || (r.op === 'contains' && (r.values.includes('/') || r.values.includes('.')))))

async function save() {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const cleaned = cleanRules()
    const res: any = await $fetch(`${config.public.apiBase}/filters`, {
      method: 'POST', headers: headers(), body: { rules: cleaned },
    })
    rules.value = res.rules ?? []
    notice.value = cleaned.length
      ? 'Matching events will no longer be stored.'
      : 'Ingest filters cleared. Every event will be stored.'
  } catch (e) {
    error.value = toDisplayMessage(e, 'The filters could not be saved.')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <v-alert v-if="!can.manageSources" type="warning" variant="tonal">
      Managing ingest filters requires source-management permission.
    </v-alert>

    <template v-else>
      <v-alert v-if="error" type="error" variant="tonal" closable class="mb-3" @click:close="error = ''">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" closable class="mb-3" @click:close="notice = ''">{{ notice }}</v-alert>
      <v-progress-linear v-if="loading || busy" indeterminate class="mb-3" />

      <v-alert type="warning" variant="tonal" class="mb-4" data-test="filter-warning">
        <strong>Filtered events cannot be recovered.</strong> They are not searchable,
        not counted in dashboards, and not kept as raw payloads. Rules apply to events
        arriving from now on — never to what is already stored.
      </v-alert>

      <v-card>
        <v-card-title class="d-flex align-center text-subtitle-1">
          Ingest filters
          <v-spacer />
          <v-btn
            size="small" variant="outlined" :disabled="rules.length >= MAX_RULES"
            data-test="add-rule" @click="addRule"
          >Add rule</v-btn>
        </v-card-title>
        <v-card-text>
          <v-alert v-if="overlyBroad" type="error" variant="tonal" class="mb-3" data-test="overly-broad">
            One of these rules matches nearly every request for this tenant.
          </v-alert>

          <div v-if="!rules.length" class="text-caption text-medium-emphasis mb-2">
            No filters: every event that authenticates is stored.
          </div>

          <div v-for="(r, i) in rules" :key="i" class="mb-4">
            <div class="d-flex ga-3 align-center flex-wrap">
              <v-select
                v-model="r.field" :items="FIELDS" density="compact" hide-details
                style="max-width: 160px" label="Field"
              />
              <v-select
                v-model="r.op" :items="OPS" density="compact" hide-details
                style="max-width: 160px" label="Condition"
              />
              <v-combobox
                v-model="r.values" multiple chips closable-chips density="compact"
                hide-details label="Values (Enter after each)" style="min-width: 260px; flex: 1"
                data-test="rule-values"
              />
              <v-btn icon="mdi-delete-outline" size="small" variant="text" @click="removeRule(i)" />
            </div>
            <div class="text-caption text-medium-emphasis mt-1">{{ describeRule(r) }}</div>
          </div>

          <v-btn color="primary" :disabled="busy" data-test="save-filters" @click="save">
            Save filters
          </v-btn>
          <span class="text-caption text-medium-emphasis ml-3">
            Changes reach ingest within 30 seconds. {{ rules.length }}/{{ MAX_RULES }} rules.
          </span>
        </v-card-text>
      </v-card>
    </template>
  </div>
</template>
