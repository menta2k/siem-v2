// The full Vuetify stylesheet, not just component styles. vite-plugin-vuetify
// auto-imports per-component styles and leaves the utility classes (d-flex,
// ga-*, justify-*) undefined, which collapses layout to block flow with no error
// anywhere to explain it.
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi'

/**
 * Theme.
 *
 * Verdict colours are defined once here and referenced everywhere, so "blocked"
 * looks identical on a dashboard, in a results table and on a request flow. An
 * analyst scanning during an incident should never have to re-learn what a
 * colour means.
 *
 * Dark is the default: this console is read for long stretches in operations
 * rooms.
 */
export default defineNuxtPlugin((app) => {
  app.vueApp.use(
    createVuetify({
      icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
      defaults: {
        VDataTable: { density: 'compact', hover: true },
        VTable: { density: 'compact', hover: true },
        VTextField: { variant: 'outlined', density: 'comfortable', hideDetails: 'auto' },
        VSelect: { variant: 'outlined', density: 'comfortable', hideDetails: 'auto' },
        VCard: { elevation: 1 },
        VBtn: { variant: 'flat' },
      },
      theme: {
        defaultTheme: 'siemDark',
        themes: {
          siemDark: {
            dark: true,
            colors: {
              background: '#0F1419',
              surface: '#171D24',
              'surface-bright': '#1F262F',
              primary: '#4C8DFF',
              secondary: '#7A8899',

              // Verdicts, most restrictive to least.
              error: '#F2555A',   // blocked
              warning: '#F0A030', // rate limited
              info: '#4C8DFF',    // challenged
              success: '#3FB950', // allowed
              'on-surface': '#E4E9F0',
            },
          },
          siemLight: {
            dark: false,
            colors: {
              background: '#F7F9FC',
              surface: '#FFFFFF',
              primary: '#1B62D6',
              secondary: '#5A6878',
              error: '#C7343A',
              warning: '#B4700C',
              info: '#1B62D6',
              success: '#1F7A32',
            },
          },
        },
      },
    }),
  )
})

/**
 * Maps a normalized action to its theme colour. One definition, used everywhere.
 *
 * `logged` is deliberately NOT styled as an allow. A layer in detection-only mode
 * did not decide to permit the request — it decided not to act — and colouring the
 * two alike would let an "everything allowed it" reading hide a layer that was
 * never enforcing at all. This is exactly DataDome's hard_block-on-a-200 case.
 */
export function actionColor(action: string): string {
  switch (action) {
    case 'blocked':
    case 'challenge_failed':
      return 'error'
    case 'rate_limited':
      return 'warning'
    case 'challenged':
      return 'info'
    case 'allowed':
    case 'challenge_passed':
      return 'success'
    case 'logged':
      return 'secondary'
    default:
      // An unmapped verdict must look different from a known one, never like a
      // benign default.
      return 'purple'
  }
}

/** Icon per action, so meaning does not rest on colour alone. */
export function actionIcon(action: string): string {
  switch (action) {
    case 'blocked':
    case 'challenge_failed':
      return 'mdi-cancel'
    case 'rate_limited':
      return 'mdi-speedometer-slow'
    case 'challenged':
      return 'mdi-help-rhombus-outline'
    case 'allowed':
    case 'challenge_passed':
      return 'mdi-check-circle-outline'
    case 'logged':
      return 'mdi-eye-outline'
    default:
      return 'mdi-help-circle-outline'
  }
}

/** Maps a join tier to a colour, so an uncertain join never looks authoritative. */
export function confidenceColor(method: string): string {
  switch (method) {
    case 'exact':
      return 'success'
    case 'heuristic':
      return 'warning'
    default:
      return 'secondary'
  }
}
