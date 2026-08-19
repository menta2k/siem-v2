<script setup lang="ts">
const { identity } = useApi()
const { user, isAuthenticated, logout } = useAuth()
const route = useRoute()

// Session restore happens in plugins/session.client.ts, before any page runs.

async function signOut() {
  await logout()
  navigateTo('/login')
}
const drawer = ref(true)

const identities = [
  { title: 'Analyst (acme)', value: 'analyst@acme.example.com' },
  { title: 'Engineer (acme)', value: 'engineer@acme.example.com' },
  { title: 'Admin (acme)', value: 'admin@acme.example.com' },
  { title: 'Analyst (globex)', value: 'analyst@globex.example.com' },
]

const tenant = computed(() => (identity.value.includes('globex') ? 'Globex Inc' : 'Acme Corp'))
const role = computed(() => identity.value.split('@')[0])

// Items are hidden when the role cannot use them. This is navigation hygiene,
// NOT access control — every route and every API call behind it is enforced
// server-side, and hiding a link protects nobody on its own.
const navItems = computed(() => [
  { title: 'Dashboards', icon: 'mdi-view-dashboard', to: '/dashboards', visible: true },
  { title: 'Search', icon: 'mdi-magnify', to: '/', visible: true },
  { title: 'Alerts', icon: 'mdi-bell-alert', to: '/alerts', visible: true },
  { title: 'Rule testing', icon: 'mdi-shield-search', to: '/evaluate', visible: true },
  { title: 'Sources', icon: 'mdi-import', to: '/sources', visible: true },
  { title: 'Feeds', icon: 'mdi-transit-connection-variant', to: '/feeds', visible: role.value === 'admin' || role.value === 'engineer' },
  { title: 'Audit', icon: 'mdi-clipboard-text-clock', to: '/audit', visible: role.value === 'admin' },
  { title: 'Users', icon: 'mdi-account-multiple', to: '/users', visible: role.value === 'admin' },
])

const visibleItems = computed(() => navItems.value.filter((i) => i.visible))

const title = computed(() => {
  const match = navItems.value.find((i) => i.to === route.path)
  if (match) return match.title
  if (route.path.startsWith('/flows/')) return 'Request flow'
  return 'SIEM v2'
})
</script>

<template>
  <v-app>
    <v-navigation-drawer v-model="drawer" :width="240" color="surface">
      <div class="pa-4">
        <div class="text-h6 d-flex align-center ga-2">
          <v-icon icon="mdi-shield-link-variant" color="primary" />
          SIEM v2
        </div>
        <div class="text-caption text-medium-emphasis">{{ tenant }}</div>
      </div>

      <v-divider />

      <v-list nav density="compact">
        <v-list-item
          v-for="item in visibleItems"
          :key="item.to"
          :to="item.to"
          :prepend-icon="item.icon"
          :title="item.title"
        />
      </v-list>

      <template #append>
        <v-divider />
        <div v-if="isAuthenticated" class="pa-3" data-test="session-block">
          <div class="text-body-2">{{ user?.email }}</div>
          <div class="text-caption text-medium-emphasis mb-2">{{ user?.role }} · {{ user?.tenant_id }}</div>
          <v-btn size="small" variant="tonal" block prepend-icon="mdi-logout" data-test="sign-out" @click="signOut">
            Sign out
          </v-btn>
        </div>
        <div v-else class="pa-3">
          <v-btn size="small" color="primary" variant="tonal" block prepend-icon="mdi-login" to="/login" class="mb-3">
            Sign in
          </v-btn>
          <v-select
            v-model="identity"
            :items="identities"
            item-title="title"
            item-value="value"
            label="Signed in as"
            density="compact"
            hide-details
            data-test="identity"
          />
          <div class="text-caption text-medium-emphasis mt-2">
            Dev identity — tenant is resolved server-side.
          </div>
        </div>
      </template>
    </v-navigation-drawer>

    <v-app-bar flat density="comfortable" color="surface">
      <v-app-bar-nav-icon @click="drawer = !drawer" />
      <v-app-bar-title>{{ title }}</v-app-bar-title>
      <v-spacer />
      <CollectionHealthBanner compact />
    </v-app-bar>

    <v-main>
      <v-container fluid class="pa-4">
        <slot />
      </v-container>
    </v-main>

    <!--
      Rendered here, not in the page. A Vuetify navigation drawer registers with
      the surrounding app layout; nested inside v-main it never registers and
      simply does not appear.
    -->
    <FlowDetailDrawer />
  </v-app>
</template>
