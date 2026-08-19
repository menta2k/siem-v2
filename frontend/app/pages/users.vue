<script setup lang="ts">
// User management, mirroring v1's Admin users tab: an invite card, a compact
// table with inline role editing, and a one-time setup link shown exactly once.
// Every control here is UX only — the server enforces manage_users per request.
const { headers } = useApi()
const { can, user: me } = useAuth()
const config = useRuntimeConfig()

const ROLES = ['analyst', 'engineer', 'admin']

const users = ref<any[]>([])
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')

// The one-time invite link. It exists only in this ref and the admin's
// clipboard — the server never returns it again.
const inviteResult = ref<{ email: string, url: string, expires: string } | null>(null)
const copied = ref(false)

const inviteEmail = ref('')
const inviteRole = ref('analyst')

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/users`, { headers: headers() })
    users.value = res.users ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'Users could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function invite(email: string, role: string) {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/invites`, {
      method: 'POST', headers: headers(), body: { email, role },
    })
    inviteResult.value = {
      email,
      url: `${window.location.origin}/invite?token=${encodeURIComponent(res.invite_token)}`,
      expires: new Date(res.expires_at).toLocaleString(),
    }
    copied.value = false
    inviteEmail.value = ''
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The invite could not be created.')
  } finally {
    busy.value = false
  }
}

async function update(u: any, body: Record<string, unknown>, doneNotice: string) {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await $fetch(`${config.public.apiBase}/users/${encodeURIComponent(u.principal_id)}`, {
      method: 'POST', headers: headers(), body,
    })
    notice.value = doneNotice
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The change could not be applied.')
    await load() // roll the optimistic select back to server truth
  } finally {
    busy.value = false
  }
}

function statusOf(u: any): { label: string, color: string } {
  if (!u.active) return { label: 'Disabled', color: 'warning' }
  if (!u.has_password) return { label: 'Awaiting setup', color: 'info' }
  return { label: 'Active', color: 'success' }
}

async function copyLink() {
  if (!inviteResult.value) return
  try {
    await navigator.clipboard.writeText(inviteResult.value.url)
    copied.value = true
  } catch {
    // Clipboard can be unavailable (permissions, http); the link stays visible.
  }
}

function lastLogin(u: any) {
  return u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'
}
</script>

<template>
  <div>
    <v-alert v-if="!can.manageUsers" type="warning" variant="tonal" data-test="users-forbidden">
      Managing users requires an administrator account.
    </v-alert>

    <template v-else>
      <v-alert v-if="error" type="error" variant="tonal" closable class="mb-3" @click:close="error = ''">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" closable class="mb-3" @click:close="notice = ''">{{ notice }}</v-alert>
      <v-progress-linear v-if="loading || busy" indeterminate class="mb-3" />

      <v-card class="mb-4" data-test="invite-card">
        <v-card-title class="text-subtitle-1">Invite a user</v-card-title>
        <v-card-text>
          <div class="d-flex flex-wrap ga-3 align-center">
            <v-text-field
              v-model="inviteEmail" label="Email" density="compact" hide-details
              style="max-width: 300px" data-test="invite-email"
            />
            <v-select
              v-model="inviteRole" :items="ROLES" label="Role" density="compact"
              hide-details style="max-width: 180px" data-test="invite-role"
            />
            <v-btn
              color="primary" :disabled="busy || !inviteEmail.includes('@')"
              data-test="invite-submit" @click="invite(inviteEmail.trim(), inviteRole)"
            >
              Invite
            </v-btn>
          </div>

          <v-alert
            v-if="inviteResult" type="info" variant="tonal" closable class="mt-4"
            data-test="invite-result" @click:close="inviteResult = null"
          >
            <div class="mb-1">
              Setup link for <strong>{{ inviteResult.email }}</strong> — it works once,
              expires {{ inviteResult.expires }}, and cannot be shown again.
            </div>
            <code class="d-block text-caption mb-2" style="word-break: break-all">{{ inviteResult.url }}</code>
            <v-btn size="small" variant="outlined" data-test="copy-invite" @click="copyLink">
              {{ copied ? 'Copied' : 'Copy link' }}
            </v-btn>
          </v-alert>
        </v-card-text>
      </v-card>

      <v-card>
        <v-card-title class="text-subtitle-1">Users</v-card-title>
        <v-card-text>
          <v-table density="compact" data-test="users-table">
            <thead>
              <tr>
                <th>Email</th><th>Role</th><th>Status</th><th>MFA</th>
                <th>Last login</th><th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in users" :key="u.principal_id">
                <td class="text-caption">{{ u.email }}</td>
                <td style="min-width: 130px">
                  <v-select
                    :model-value="u.role" :items="ROLES" density="compact"
                    variant="plain" hide-details
                    :disabled="busy || u.principal_id === me?.principal_id"
                    @update:model-value="(r: string) => update(u, { role: r }, `Role for ${u.email} is now ${r}.`)"
                  />
                </td>
                <td>
                  <v-chip size="x-small" variant="tonal" :color="statusOf(u).color">
                    {{ statusOf(u).label }}
                  </v-chip>
                </td>
                <td>
                  <v-chip size="x-small" variant="tonal" :color="u.mfa_enrolled ? 'success' : 'warning'">
                    {{ u.mfa_enrolled ? 'Enrolled' : 'Not enrolled' }}
                  </v-chip>
                </td>
                <td class="text-caption">{{ lastLogin(u) }}</td>
                <td class="text-right text-no-wrap">
                  <v-btn
                    v-if="u.active" size="x-small" variant="text" :disabled="busy"
                    @click="invite(u.email, u.role)"
                  >
                    {{ u.invite_pending || !u.has_password ? 'New setup link' : 'Send reset link' }}
                  </v-btn>
                  <v-btn
                    v-if="u.mfa_enrolled" size="x-small" variant="text" :disabled="busy"
                    @click="update(u, { reset_mfa: true }, `MFA for ${u.email} was reset; their next sign-in re-enrols.`)"
                  >
                    Reset MFA
                  </v-btn>
                  <v-btn
                    v-if="u.active && u.principal_id !== me?.principal_id"
                    size="x-small" variant="text" color="warning" :disabled="busy"
                    @click="update(u, { active: false }, `${u.email} can no longer sign in.`)"
                  >
                    Disable
                  </v-btn>
                  <v-btn
                    v-if="!u.active" size="x-small" variant="text" color="success" :disabled="busy"
                    @click="update(u, { active: true }, `${u.email} can sign in again.`)"
                  >
                    Enable
                  </v-btn>
                </td>
              </tr>
              <tr v-if="!loading && users.length === 0">
                <td colspan="6" class="text-caption text-medium-emphasis">No users in this tenant.</td>
              </tr>
            </tbody>
          </v-table>
        </v-card-text>
      </v-card>
    </template>
  </div>
</template>
