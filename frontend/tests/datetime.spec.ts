import { describe, expect, it } from 'vitest'
import {
  BROWSER_DEFAULT, COMMON_TIME_ZONES, formatDateTime, formatTimeOfDay, isValidTimeZone,
} from '../app/lib/datetime'

const instant = '2026-08-20T12:00:00Z'

describe('datetime formatting', () => {
  it('renders the same instant differently per zone', () => {
    const utc = formatDateTime(instant, { timeZone: 'UTC', hourFormat: '24' })
    const sofia = formatDateTime(instant, { timeZone: 'Europe/Sofia', hourFormat: '24' })
    const tokyo = formatDateTime(instant, { timeZone: 'Asia/Tokyo', hourFormat: '24' })
    expect(utc).toContain('12:00:00')
    expect(sofia).toContain('15:00:00') // EEST, +3 in August
    expect(tokyo).toContain('21:00:00')
  })

  it('honours the hour format', () => {
    const h12 = formatDateTime(instant, { timeZone: 'UTC', hourFormat: '12' })
    expect(h12.toLowerCase()).toMatch(/pm|noon/)
    const h24 = formatTimeOfDay(instant, { timeZone: 'UTC', hourFormat: '24' })
    expect(h24).toContain('12:00:00')
  })

  it('renders placeholders for absent values, never "Invalid Date"', () => {
    for (const v of [null, undefined, '', 'not-a-date']) {
      expect(formatDateTime(v as never, BROWSER_DEFAULT, 'Never')).toBe('Never')
    }
  })

  it('validates zones and accepts the browser-default sentinel', () => {
    expect(isValidTimeZone('')).toBe(true)
    expect(isValidTimeZone('Europe/Sofia')).toBe(true)
    expect(isValidTimeZone('Not/AZone')).toBe(false)
    for (const z of COMMON_TIME_ZONES) expect(isValidTimeZone(z)).toBe(true)
  })
})
