import {
  BROWSER_DEFAULT, formatDateTime, formatTimeOfDay, isValidTimeZone,
  type TimeFormat,
} from '~/lib/datetime'

const STORAGE_KEY = 'siem.preferences.time'

/**
 * Per-user display preferences (ported from v1). localStorage-only: the
 * preference changes how instants RENDER, never what is stored, so it needs
 * no backend and follows the browser profile like any other display setting.
 */
export function usePrefs() {
  const format = useState<TimeFormat>('prefs-time', () => {
    if (import.meta.client) {
      try {
        const raw = localStorage.getItem(STORAGE_KEY)
        if (raw) {
          const parsed = JSON.parse(raw)
          return {
            timeZone: isValidTimeZone(parsed.timeZone) ? parsed.timeZone : '',
            hourFormat: ['12', '24'].includes(parsed.hourFormat) ? parsed.hourFormat : 'auto',
          }
        }
      } catch {
        // Malformed storage falls back to the browser default silently.
      }
    }
    return { ...BROWSER_DEFAULT }
  })

  function persist() {
    if (import.meta.client) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(format.value))
      } catch {
        // Storage can be disabled; the in-memory value still applies.
      }
    }
  }

  const browserZone = computed(() =>
    import.meta.client ? (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC') : 'UTC')
  const activeTimeZone = computed(() => format.value.timeZone || browserZone.value)
  const followsBrowser = computed(() => format.value.timeZone === '')

  function setTimeZone(zone: string) {
    format.value = { ...format.value, timeZone: isValidTimeZone(zone) ? zone : '' }
    persist()
  }
  function setHourFormat(h: TimeFormat['hourFormat']) {
    format.value = { ...format.value, hourFormat: h }
    persist()
  }
  function reset() {
    format.value = { ...BROWSER_DEFAULT }
    persist()
  }

  const dateTime = (v: string | number | Date | null | undefined, placeholder = '—') =>
    formatDateTime(v, format.value, placeholder)
  const timeOfDay = (v: string | number | Date | null | undefined, placeholder = '—') =>
    formatTimeOfDay(v, format.value, placeholder)

  return {
    format, browserZone, activeTimeZone, followsBrowser,
    setTimeZone, setHourFormat, reset, dateTime, timeOfDay,
  }
}
