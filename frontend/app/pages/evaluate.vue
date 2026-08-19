<script setup lang="ts">
const { evaluate } = useApi()
const form = reactive({
  method: 'GET',
  uri: "/search?q=1' OR '1'='1",
  client_ip: '203.0.113.9',
  paranoia_level: 1,
})
const result = ref<any>(null)
const loading = ref(false)
const error = ref('')

async function run() {
  loading.value = true; error.value = ''
  try {
    result.value = await evaluate({ ...form, headers: { Host: 'shop.example.com', 'User-Agent': 'curl/8.0' } })
  } catch (e: any) {
    error.value = toDisplayMessage(e, 'The evaluation could not be completed.')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div>
    <v-card class="mb-4">
      <v-card-title class="text-subtitle-1">Test a request against OWASP CRS</v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col cols="2"><v-text-field v-model="form.method" label="Method" density="compact" hide-details /></v-col>
          <v-col cols="6"><v-text-field v-model="form.uri" label="URI" density="compact" hide-details data-test="uri" /></v-col>
          <v-col cols="2"><v-text-field v-model="form.client_ip" label="Client IP" density="compact" hide-details /></v-col>
          <v-col cols="2">
            <v-select v-model.number="form.paranoia_level" :items="[1,2,3,4]" label="Paranoia" density="compact" hide-details />
          </v-col>
        </v-row>
        <v-btn color="primary" class="mt-3" :loading="loading" data-test="evaluate" @click="run">Evaluate</v-btn>
      </v-card-text>
    </v-card>

    <v-alert v-if="error" type="error" variant="tonal">{{ error }}</v-alert>

    <v-card v-if="result" data-test="eval-result">
      <v-card-text>
        <div class="d-flex ga-3 align-center mb-3">
          <v-chip :color="result.would_block ? 'error' : 'success'" label data-test="would-block">
            {{ result.would_block ? 'would block' : 'would allow' }}
          </v-chip>
          <span>score <strong>{{ result.anomaly_score }}</strong> / threshold {{ result.threshold }}</span>
          <v-spacer />
          <span class="text-caption text-medium-emphasis">
            {{ result.engine_version }} · {{ result.ruleset_version }} · PL{{ result.paranoia_level }}
          </span>
        </div>

        <v-alert v-if="result.warnings?.length" type="warning" variant="tonal" density="compact" class="mb-3">
          <div v-for="w in result.warnings" :key="w" class="text-caption">{{ w }}</div>
        </v-alert>

        <v-table density="compact">
          <thead><tr><th>Rule</th><th>Severity</th><th>Message</th></tr></thead>
          <tbody>
            <tr v-for="m in (result.matched_rules || []).filter((r:any) => r.message)" :key="m.rule_id">
              <td class="text-caption">{{ m.rule_id }}</td>
              <td class="text-caption">{{ m.severity }}</td>
              <td class="text-caption">{{ m.message }}</td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>
  </div>
</template>
