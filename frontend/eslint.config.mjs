// @ts-check
import withNuxt from './.nuxt/eslint.config.mjs'

export default withNuxt(
  {
    rules: {
      // API payload shapes are owned by the backend contract; the pages read
      // them as `any` at the boundary deliberately, and vue-tsc --strict is
      // the type gate. Warn keeps the signal without failing the build.
      '@typescript-eslint/no-explicit-any': 'warn',
      // Props with clear absent-state handling don't all need defaults.
      'vue/require-default-prop': 'warn',
    },
  },
)
