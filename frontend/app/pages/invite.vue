<script setup lang="ts">
// One-time account setup. The token arrives in the URL, lives only in this
// component, and is never stored anywhere durable. Preview does not spend the
// token, so a dead link fails before the user types a password.
definePageMeta({ layout: 'bare' })

const config = useRuntimeConfig()
const route = useRoute()

const MIN_PASSWORD_LENGTH = 12 // mirrors the server's auth.MinPasswordLength

const token = computed(() => String(route.query.token ?? ''))
const checking = ref(true)
const email = ref('')
const role = ref('')
const error = ref('')
const done = ref(false)
const busy = ref(false)

const password = ref('')
const confirm = ref('')

const tooShort = computed(() => password.value.length > 0 && password.value.length < MIN_PASSWORD_LENGTH)
const mismatch = computed(() => confirm.value.length > 0 && confirm.value !== password.value)
const canSubmit = computed(() =>
  password.value.length >= MIN_PASSWORD_LENGTH && confirm.value === password.value && !busy.value)

onMounted(async () => {
  if (!token.value) {
    error.value = 'This setup link is missing its token. Ask an administrator for a new one.'
    checking.value = false
    return
  }
  try {
    const res: any = await $fetch(`${config.public.apiBase}/invites/preview`, {
      query: { token: token.value },
    })
    email.value = res.email
    role.value = res.role
  } catch {
    error.value = 'This setup link is not usable. It may have expired or already been used — ask an administrator for a new one.'
  } finally {
    checking.value = false
  }
})

async function redeem() {
  busy.value = true; error.value = ''
  try {
    await $fetch(`${config.public.apiBase}/invites/redeem`, {
      method: 'POST', body: { token: token.value, password: password.value },
    })
    done.value = true
  } catch (e) {
    error.value = toDisplayMessage(e, 'The password could not be set.')
  } finally {
    // The password never outlives the attempt, whichever way it went.
    password.value = ''
    confirm.value = ''
    busy.value = false
  }
}
</script>

<template>
  <v-app>
    <v-main class="d-flex align-center justify-center" style="min-height: 100vh">
      <v-container>
        <v-row justify="center">
          <v-col cols="12" sm="8" md="5" lg="4">
          <v-card class="pa-6">
            <div class="text-h5 mb-1">SIEM v2</div>
            <div class="text-caption text-medium-emphasis mb-4">Account setup</div>

            <v-progress-circular v-if="checking" indeterminate class="mb-2" />
            <v-alert v-if="error" type="error" variant="tonal" class="mb-3" data-test="invite-error">{{ error }}</v-alert>

            <template v-if="done">
              <v-alert type="success" variant="tonal" class="mb-4" data-test="invite-done">
                Your password is set. Signing in will walk you through setting up
                your authenticator app.
              </v-alert>
              <v-btn color="primary" block to="/login">Sign in</v-btn>
            </template>

            <v-form v-else-if="email && !checking" data-test="invite-form" @submit.prevent="canSubmit && redeem()">
              <v-alert type="info" variant="tonal" class="mb-4">
                Choose a password for <strong>{{ email }}</strong> ({{ role }}).
                This link works once.
              </v-alert>
              <v-text-field
                v-model="password" label="Password" type="password"
                autocomplete="new-password" autofocus
                :error-messages="tooShort ? `Use at least ${MIN_PASSWORD_LENGTH} characters` : ''"
                data-test="invite-password"
              />
              <v-text-field
                v-model="confirm" label="Confirm password" type="password"
                autocomplete="new-password"
                :error-messages="mismatch ? 'The two passwords do not match' : ''"
                data-test="invite-confirm"
              />
              <v-btn color="primary" type="submit" block :disabled="!canSubmit" :loading="busy">
                Set password
              </v-btn>
            </v-form>
          </v-card>
          </v-col>
        </v-row>
      </v-container>
    </v-main>
  </v-app>
</template>
