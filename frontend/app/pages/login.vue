<script setup lang="ts">
import QRCode from 'qrcode'

definePageMeta({ layout: 'bare' })

const { login, verifyMfa, awaitingMfa, enrolling, provisioningUri, refresh } = useAuth()

// Where to land after a successful sign-in: the page the guard bounced us from,
// or the home page. Only same-origin app paths are honoured — never an
// absolute URL an attacker could stuff into ?redirect= for an open redirect.
const route = useRoute()
const redirectTo = computed(() => {
  const r = route.query.redirect
  return typeof r === 'string' && r.startsWith('/') && !r.startsWith('//') ? r : '/'
})

const email = ref('')
const password = ref('')
const code = ref('')
const error = ref('')
const busy = ref(false)
const qrDataUrl = ref('')

// A reload with a live refresh cookie signs straight back in.
onMounted(async () => {
  if (await refresh()) navigateTo(redirectTo.value)
})

// The QR is rendered client-side from the provisioning URI — the secret never
// travels anywhere except inside that URI, once, during enrolment.
watch(provisioningUri, async (uri) => {
  qrDataUrl.value = uri ? await QRCode.toDataURL(uri, { width: 220, margin: 1 }) : ''
})

async function submitPassword() {
  busy.value = true
  error.value = ''
  try {
    const complete = await login(email.value.trim(), password.value)
    if (complete) {
      navigateTo(redirectTo.value)
      return
    }
  } catch (e) {
    error.value = toDisplayMessage(e, 'Sign-in did not succeed.')
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  busy.value = true
  error.value = ''
  try {
    await verifyMfa(code.value.trim())
    navigateTo(redirectTo.value)
  } catch (e) {
    error.value = toDisplayMessage(e, 'The code did not verify.')
    code.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-app>
    <v-main class="d-flex align-center justify-center" style="min-height: 100vh">
      <v-card width="420" class="pa-2">
        <v-card-title class="d-flex align-center ga-2">
          <v-icon icon="mdi-shield-link-variant" color="primary" />
          SIEM v2
        </v-card-title>

        <v-card-text>
          <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" data-test="login-error">
            {{ error }}
          </v-alert>

          <!-- Step one: password -->
          <v-form v-if="!awaitingMfa" data-test="password-step" @submit.prevent="submitPassword">
            <v-text-field
              v-model="email" label="Email" type="email" autocomplete="username"
              prepend-inner-icon="mdi-email-outline" class="mb-3" data-test="email"
            />
            <v-text-field
              v-model="password" label="Password" type="password" autocomplete="current-password"
              prepend-inner-icon="mdi-lock-outline" class="mb-4" data-test="password"
            />
            <v-btn type="submit" color="primary" block :loading="busy" data-test="sign-in">
              Sign in
            </v-btn>
          </v-form>

          <!-- Step two: TOTP, with enrolment when this is the first sign-in -->
          <v-form v-else data-test="mfa-step" @submit.prevent="submitCode">
            <template v-if="enrolling">
              <p class="text-body-2 mb-3">
                Scan this with your authenticator app, then enter the code it shows.
                Enrolment completes only when a code verifies — if the scan failed,
                signing in again issues a fresh one.
              </p>
              <div class="text-center mb-3">
                <img v-if="qrDataUrl" :src="qrDataUrl" alt="TOTP enrolment QR code" data-test="qr">
              </div>
              <details class="text-caption text-medium-emphasis mb-3">
                <summary>Can't scan? Enter the key manually</summary>
                <code class="text-break">{{ provisioningUri }}</code>
              </details>
            </template>
            <p v-else class="text-body-2 mb-3">
              Enter the current code from your authenticator app.
            </p>

            <v-text-field
              v-model="code" label="6-digit code" inputmode="numeric" autocomplete="one-time-code"
              maxlength="6" prepend-inner-icon="mdi-cellphone-key" class="mb-4" data-test="code"
            />
            <v-btn type="submit" color="primary" block :loading="busy" data-test="verify">
              Verify
            </v-btn>
          </v-form>
        </v-card-text>
      </v-card>
    </v-main>
  </v-app>
</template>
