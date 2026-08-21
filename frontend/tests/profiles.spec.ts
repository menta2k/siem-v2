import { describe, expect, it } from 'vitest'
import {
  ceiling, compact, statusMixSlices, templateSegments, typeComposition,
} from '../app/lib/profiles'

describe('templateSegments', () => {
  it('marks parameter tokens and keeps literals', () => {
    const segs = templateSegments('/job/{int}/apply')
    expect(segs).toEqual([
      { text: 'job', isParam: false },
      { text: '{int}', isParam: true },
      { text: 'apply', isParam: false },
    ])
  })

  it('renders the root path as a single literal', () => {
    expect(templateSegments('/')).toEqual([{ text: '/', isParam: false }])
  })
})

describe('statusMixSlices', () => {
  it('buckets exact statuses into classes with shares that sum to 1', () => {
    const slices = statusMixSlices({ 200: 60, 204: 20, 404: 15, 500: 5 })
    expect(slices.map(s => s.cls)).toEqual(['2xx', '4xx', '5xx'])
    expect(slices.map(s => s.count)).toEqual([80, 15, 5])
    expect(slices.reduce((a, s) => a + s.share, 0)).toBeCloseTo(1)
  })

  it('handles an absent mix without inventing data', () => {
    expect(statusMixSlices(null)).toEqual([])
    expect(statusMixSlices({})).toEqual([])
  })
})

describe('ceiling', () => {
  it('renders null as "not captured", never 0 — an absent measurement is not a measured zero', () => {
    expect(ceiling(null)).toBe('not captured')
    expect(ceiling(undefined)).toBe('not captured')
    expect(ceiling(0)).toBe('0')
    expect(ceiling(1536, 'B')).toBe('1.5 KiB')
  })
})

describe('typeComposition', () => {
  it('aggregates by type, largest first', () => {
    const slices = typeComposition([
      { inferred_type: 'int' }, { inferred_type: 'int' }, { inferred_type: 'freetext' },
    ])
    expect(slices[0]).toMatchObject({ cls: 'int', count: 2 })
    expect(slices[1]).toMatchObject({ cls: 'freetext', count: 1 })
    expect(slices.reduce((a, s) => a + s.share, 0)).toBeCloseTo(1)
  })
})

describe('compact', () => {
  it('keeps small numbers exact and compresses large ones', () => {
    expect(compact(841)).toBe('841')
    expect(compact(12841)).toBe('13k')
    expect(compact(2_400_000)).toBe('2.4M')
  })
})
