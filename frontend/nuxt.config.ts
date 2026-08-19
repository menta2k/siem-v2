import vuetify, { transformAssetUrls } from 'vite-plugin-vuetify'

export default defineNuxtConfig({
  compatibilityDate: '2026-08-19',
  // Nuxt 3 defaults srcDir to the project root; this project keeps application
  // code under app/ (the Nuxt 4 convention), so it must be declared explicitly
  // or app.vue and pages/ are silently ignored and the welcome page is served.
  srcDir: 'app/',
  ssr: false, // an operator console; no SEO need, and it keeps deployment to static assets
  modules: [
    (_options, nuxt) => {
      nuxt.hooks.hook('vite:extendConfig', (config) => {
        config.plugins!.push(vuetify({ autoImport: true }))
      })
    },
    '@nuxt/eslint',
  ],
  build: { transpile: ['vuetify'] },
  vite: { vue: { template: { transformAssetUrls } } },
  runtimeConfig: {
    public: {
      // The frontend never talks to VictoriaLogs directly: every read goes
      // through the backend so tenant scope is enforced server-side (R8).
      apiBase: process.env.NUXT_PUBLIC_API_BASE || 'http://localhost:8000/api/v1',
      // Where providers deliver logs (the logproc ingest listener) — used only
      // to render copy-paste URLs, never called by the browser.
      ingestBase: process.env.NUXT_PUBLIC_INGEST_BASE || 'http://localhost:8100',
    },
  },
  typescript: { strict: true },
})
