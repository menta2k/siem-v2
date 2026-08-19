<script setup lang="ts">
const { identity, headers } = useApi()
const config = useRuntimeConfig()

const entries = ref<any[]>([])
const loading = ref(false)
const error = ref('')

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/audit`, {
      headers: headers(),
    })
    entries.value = res.entries ?? []
  } catch (e) {
    // An analyst gets "Not found" here rather than "forbidden", by design: the
    // refusal must not reveal that an audit endpoint exists.
    error.value = toDisplayMessage(e, 'The audit trail is not available to you.')
    entries.value = []
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(identity, load)
</script>

<template>
  <div>
    <v-alert v-if="error" type="warning" variant="tonal" class="mb-3" data-test="audit-error">{{ error }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate class="mb-3" />

    <v-card v-if="entries.length">
      <v-card-title class="text-subtitle-1">
        Audit trail
        <v-chip
size="x-small" variant="outlined" class="ml-2"
          title="Append-only: the database rejects UPDATE, DELETE and TRUNCATE on this table.">
          append-only
        </v-chip>
      </v-card-title>
      <v-card-text>
        <v-table density="compact" data-test="audit-entries">
          <thead>
            <tr><th>When</th><th>Principal</th><th>Action</th><th>Target</th><th>Outcome</th></tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in entries" :key="i">
              <td class="text-caption">{{ new Date(e.OccurredAt ?? e.occurred_at).toISOString().replace('T',' ').slice(0,19) }}</td>
              <td class="text-caption">{{ e.PrincipalID ?? e.principal_id }}</td>
              <td class="text-caption">{{ e.Action ?? e.action }}</td>
              <td class="text-caption">{{ e.TargetRef ?? e.target_ref }}</td>
              <td>
                <v-chip size="x-small" :color="(e.Outcome ?? e.outcome) === 'denied' ? 'error' : 'success'" variant="tonal">
                  {{ e.Outcome ?? e.outcome }}
                </v-chip>
              </td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>
  </div>
</template>
