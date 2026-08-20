// Time formatting with a user-chosen zone (ported from v1).
//
// The preference is DISPLAY-only, which is why it lives client-side: the
// stored data is UTC everywhere, and two analysts in different zones looking
// at the same flow see the same instant rendered their own way.

export interface TimeFormat {
  /** IANA zone name, or '' meaning "follow the browser". */
  timeZone: string
  hourFormat: 'auto' | '12' | '24'
}

export const BROWSER_DEFAULT: TimeFormat = { timeZone: '', hourFormat: 'auto' }

/** A curated list beats the 400-entry IANA catalogue for a dropdown. */
export const COMMON_TIME_ZONES = [
  'UTC',
  'Europe/Sofia',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Moscow',
  'America/New_York',
  'America/Chicago',
  'America/Los_Angeles',
  'Asia/Dubai',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
]

export function isValidTimeZone(zone: string): boolean {
  if (!zone) return true // '' = browser default
  try {
    Intl.DateTimeFormat(undefined, { timeZone: zone })
    return true
  } catch {
    return false
  }
}

const DATE_TIME: Intl.DateTimeFormatOptions = {
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
}
const TIME_ONLY: Intl.DateTimeFormatOptions = {
  hour: '2-digit', minute: '2-digit', second: '2-digit',
}

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  const d = value instanceof Date ? value : new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

function optionsFor(base: Intl.DateTimeFormatOptions, format: TimeFormat): Intl.DateTimeFormatOptions {
  const opts: Intl.DateTimeFormatOptions = { ...base }
  if (format.timeZone) opts.timeZone = format.timeZone
  if (format.hourFormat === '12') opts.hour12 = true
  if (format.hourFormat === '24') opts.hour12 = false
  return opts
}

function render(value: string | number | Date | null | undefined,
  base: Intl.DateTimeFormatOptions, format: TimeFormat, placeholder: string): string {
  const d = toDate(value)
  if (!d) return placeholder
  try {
    return d.toLocaleString(undefined, optionsFor(base, format))
  } catch {
    // A zone Intl rejects must degrade to SOMETHING readable, not throw
    // through a table render.
    return d.toLocaleString()
  }
}

export function formatDateTime(value: string | number | Date | null | undefined,
  format: TimeFormat, placeholder = '—'): string {
  return render(value, DATE_TIME, format, placeholder)
}

export function formatTimeOfDay(value: string | number | Date | null | undefined,
  format: TimeFormat, placeholder = '—'): string {
  return render(value, TIME_ONLY, format, placeholder)
}
