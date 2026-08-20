<script setup lang="ts">
// Feed management, ported from v1: each feed is one ingest endpoint with its
// own token. The token appears exactly once — at creation or rotation — in a
// persistent dialog with ready-to-paste provider configuration; the server
// keeps only a hash and can never show it again.
const { headers } = useApi()
const { can } = useAuth()
const { dateTime } = usePrefs()
const config = useRuntimeConfig()

const PROVIDERS = ['cloudflare', 'datadome', 'f5asm', 'nginx']

const feeds = ref<any[]>([])
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')

const createOpen = ref(false)
const createProvider = ref('nginx')
const createName = ref('')

// Rotation is deliberate: a confirm dialog first (v1 wording — the old token
// dies immediately; providers retry, so nothing is lost), then the one-time
// token dialog.
const rotateTarget = ref<any | null>(null)

const tokenDialog = ref<{ feed: any, token: string } | null>(null)
const copiedWhat = ref('')

function ingestURL(feed: any) {
  return `${config.public.ingestBase}/ingest/v1/${feed.provider}/${feed.id}`
}

// Cloudflare cannot set arbitrary headers on a Logpush destination; the
// header travels as a header_-prefixed, URL-encoded query parameter (v1's
// battle-tested template).
function logpushDestination(feed: any, token: string) {
  return `${ingestURL(feed)}?header_Authorization=Bearer%20${encodeURIComponent(token)}`
}

async function load() {
  loading.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/feeds`, { headers: headers() })
    feeds.value = res.feeds ?? []
  } catch (e) {
    error.value = toDisplayMessage(e, 'Feeds could not be loaded.')
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function createFeed() {
  busy.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/feeds`, {
      method: 'POST', headers: headers(),
      body: { provider: createProvider.value, name: createName.value.trim() },
    })
    createOpen.value = false
    createName.value = ''
    tokenDialog.value = { feed: res.feed, token: res.token }
    copiedWhat.value = ''
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The feed could not be created.')
  } finally {
    busy.value = false
  }
}

async function rotate(feed: any) {
  busy.value = true; error.value = ''
  try {
    const res: any = await $fetch(`${config.public.apiBase}/feeds/${encodeURIComponent(feed.id)}/rotate`, {
      method: 'POST', headers: headers(),
    })
    rotateTarget.value = null
    tokenDialog.value = { feed, token: res.token }
    copiedWhat.value = ''
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The token could not be rotated.')
  } finally {
    busy.value = false
  }
}

async function setEnabled(feed: any, enabled: boolean) {
  busy.value = true; error.value = ''
  try {
    await $fetch(`${config.public.apiBase}/feeds/${encodeURIComponent(feed.id)}`, {
      method: 'POST', headers: headers(), body: { enabled },
    })
    notice.value = enabled
      ? `${feed.name} accepts deliveries again.`
      : `${feed.name} is disabled; its token stops working at the next refresh (within 30s).`
    await load()
  } catch (e) {
    error.value = toDisplayMessage(e, 'The change could not be applied.')
  } finally {
    busy.value = false
  }
}

async function copy(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedWhat.value = what
    setTimeout(() => { if (copiedWhat.value === what) copiedWhat.value = '' }, 2000)
  } catch {
    // Clipboard can be unavailable; the value stays visible for manual copy.
  }
}
</script>

<template>
  <div>
    <v-alert v-if="!can.manageSources" type="warning" variant="tonal">
      Managing feeds requires source-management permission.
    </v-alert>

    <template v-else>
      <v-alert v-if="error" type="error" variant="tonal" closable class="mb-3" @click:close="error = ''">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" closable class="mb-3" @click:close="notice = ''">{{ notice }}</v-alert>
      <v-progress-linear v-if="loading || busy" indeterminate class="mb-3" />

      <v-card>
        <v-card-title class="d-flex align-center text-subtitle-1">
          Ingest feeds
          <v-spacer />
          <v-btn color="primary" size="small" data-test="new-feed" @click="createOpen = true">New feed</v-btn>
        </v-card-title>
        <v-card-text>
          <v-table density="compact" data-test="feeds-table">
            <thead>
              <tr>
                <th>Provider</th><th>Name</th><th>Ingest URL</th>
                <th>Token rotated</th><th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="f in feeds" :key="f.id">
                <td class="text-caption">{{ f.provider }}</td>
                <td>
                  <div class="text-caption">
                    {{ f.name }}
                    <v-chip v-if="!f.enabled" size="x-small" variant="tonal" color="warning" class="ml-1">disabled</v-chip>
                  </div>
                  <div class="text-caption text-medium-emphasis" style="font-family: monospace">{{ f.id }}</div>
                </td>
                <td>
                  <v-btn size="x-small" variant="text" @click="copy(ingestURL(f), f.id)">
                    {{ copiedWhat === f.id ? 'Copied' : 'Copy URL' }}
                  </v-btn>
                </td>
                <td class="text-caption">{{ dateTime(f.token_rotated_at) }}</td>
                <td class="text-right text-no-wrap">
                  <v-btn size="x-small" variant="text" :disabled="busy" data-test="rotate" @click="rotateTarget = f">
                    Rotate token
                  </v-btn>
                  <v-btn
                    v-if="f.enabled" size="x-small" variant="text" color="warning" :disabled="busy"
                    @click="setEnabled(f, false)"
                  >Disable</v-btn>
                  <v-btn
                    v-else size="x-small" variant="text" color="success" :disabled="busy"
                    @click="setEnabled(f, true)"
                  >Enable</v-btn>
                </td>
              </tr>
              <tr v-if="!loading && feeds.length === 0">
                <td colspan="5" class="text-caption text-medium-emphasis">
                  No feeds yet. Each feed is one delivery endpoint with its own token.
                </td>
              </tr>
            </tbody>
          </v-table>
        </v-card-text>
      </v-card>

      <!-- Create -->
      <v-dialog v-model="createOpen" max-width="480">
        <v-card class="pa-2">
          <v-card-title class="text-subtitle-1">New feed</v-card-title>
          <v-card-text>
            <v-select v-model="createProvider" :items="PROVIDERS" label="Provider" density="compact" data-test="feed-provider" />
            <v-text-field v-model="createName" label="Name" density="compact" hint="e.g. edge-production" persistent-hint data-test="feed-name" />
          </v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn variant="text" @click="createOpen = false">Cancel</v-btn>
            <v-btn color="primary" :disabled="busy || !createName.trim()" data-test="feed-create" @click="createFeed">Create</v-btn>
          </v-card-actions>
        </v-card>
      </v-dialog>

      <!-- Rotate confirm (v1 wording kept) -->
      <v-dialog :model-value="!!rotateTarget" max-width="520" @update:model-value="rotateTarget = null">
        <v-card v-if="rotateTarget" class="pa-2">
          <v-card-title class="text-subtitle-1">Rotate the token for {{ rotateTarget.name }}?</v-card-title>
          <v-card-text>
            <v-alert type="warning" variant="tonal">
              This takes effect immediately: deliveries with the current token are
              rejected with 401 until the provider is reconfigured. Providers retry
              failed deliveries, so nothing is lost during the switch.
            </v-alert>
          </v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn variant="text" @click="rotateTarget = null">Cancel</v-btn>
            <v-btn color="warning" :disabled="busy" data-test="rotate-confirm" @click="rotate(rotateTarget)">Rotate now</v-btn>
          </v-card-actions>
        </v-card>
      </v-dialog>

      <!-- One-time token (persistent: dismissing is a deliberate act) -->
      <v-dialog :model-value="!!tokenDialog" max-width="640" persistent>
        <v-card v-if="tokenDialog" class="pa-2">
          <v-card-title class="text-subtitle-1">New ingest token</v-card-title>
          <v-card-text>
            <v-alert type="info" variant="tonal" class="mb-3">
              This token for <strong>{{ tokenDialog.feed.name }}</strong> is shown once
              and cannot be recovered — only rotated again.
            </v-alert>

            <div class="text-caption mb-1">Token</div>
            <code class="d-block text-caption mb-2" style="word-break: break-all" data-test="feed-token">{{ tokenDialog.token }}</code>
            <v-btn size="small" variant="outlined" class="mb-4" @click="copy(tokenDialog.token, 'token')">
              {{ copiedWhat === 'token' ? 'Copied' : 'Copy token' }}
            </v-btn>

            <template v-if="tokenDialog.feed.provider === 'cloudflare'">
              <div class="text-caption mb-1">Logpush destination (paste into destination_conf)</div>
              <code class="d-block text-caption mb-2" style="word-break: break-all">{{ logpushDestination(tokenDialog.feed, tokenDialog.token) }}</code>
              <v-btn size="small" variant="outlined" @click="copy(logpushDestination(tokenDialog.feed, tokenDialog.token), 'dest')">
                {{ copiedWhat === 'dest' ? 'Copied' : 'Copy destination' }}
              </v-btn>
            </template>
            <template v-else>
              <div class="text-caption mb-1">Endpoint (Vector sink URI; send the token as Authorization: Bearer)</div>
              <code class="d-block text-caption mb-2" style="word-break: break-all">{{ ingestURL(tokenDialog.feed) }}</code>
              <v-btn size="small" variant="outlined" @click="copy(ingestURL(tokenDialog.feed), 'url')">
                {{ copiedWhat === 'url' ? 'Copied' : 'Copy URL' }}
              </v-btn>
            </template>
          </v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn color="primary" data-test="token-saved" @click="tokenDialog = null">I have saved it</v-btn>
          </v-card-actions>
        </v-card>
      </v-dialog>
    </template>
  </div>
</template>
