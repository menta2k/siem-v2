import { describe, it, expect } from 'vitest'

/**
 * The terminating-layer rule, as a unit test rather than only a visual check.
 *
 * Several layers may each report a terminating ACTION — the edge blocks, and the
 * WAF would also have blocked — but only the first in causal order actually
 * ended the request. Rendering "terminated here" on each would claim the request
 * was terminated more than once, which is impossible and misattributes the block.
 */
function chipFor(layer: string, verdictTerminating: boolean, flowTerminatingLayer: string) {
  if (layer === flowTerminatingLayer) return 'terminated here'
  if (verdictTerminating) return 'superseded'
  return null
}

describe('flow timeline terminating chip', () => {
  it('marks exactly one layer as terminating', () => {
    const flowTerminatingLayer = 'edge'
    const layers = [
      { layer: 'edge', terminating: true },
      { layer: 'bot_management', terminating: true },
      { layer: 'origin', terminating: false },
    ]
    const chips = layers.map((l) => chipFor(l.layer, l.terminating, flowTerminatingLayer))
    expect(chips.filter((c) => c === 'terminated here')).toHaveLength(1)
  })

  it('marks a later terminating action as superseded, not as a second termination', () => {
    expect(chipFor('bot_management', true, 'edge')).toBe('superseded')
  })

  it('leaves non-terminating layers unmarked', () => {
    expect(chipFor('origin', false, 'edge')).toBeNull()
  })

  it('marks nothing when no layer terminated the request', () => {
    const chips = ['edge', 'origin'].map((l) => chipFor(l, false, ''))
    expect(chips.every((c) => c === null)).toBe(true)
  })
})

/**
 * Confidence presentation, mirroring the predecessor's finding that an exact join
 * spanning multiple records from one provider is NOT ambiguous.
 */
function confidenceLabel(method: string, confidence: number, bridged: boolean) {
  if (method === 'exact') return bridged ? 'exact · bridged' : 'exact'
  if (method === 'heuristic') return `heuristic · ${confidence.toFixed(2)}`
  return 'uncorrelated'
}

describe('confidence chip', () => {
  it('does not hedge an exact join', () => {
    expect(confidenceLabel('exact', 1, false)).toBe('exact')
  })

  it('names a bridged join without downgrading it', () => {
    // Bridging reaches through a record carrying two identifier spaces; it is
    // still exact and still clock-independent.
    expect(confidenceLabel('exact', 1, true)).toBe('exact · bridged')
  })

  it('shows the score on a heuristic join rather than hiding it', () => {
    expect(confidenceLabel('heuristic', 0.7, false)).toBe('heuristic · 0.70')
  })
})

/**
 * Vue casts an absent boolean prop to false. A `mapped` prop left unset would
 * therefore read as "unrecognised verdict" and stamp an unmapped marker on every
 * badge — telling analysts the whole system had stopped understanding its inputs.
 */
function showsUnmapped(mapped: boolean | undefined) {
  const withDefault = mapped ?? true
  return !withDefault
}

describe('verdict badge defaults', () => {
  it('does not claim a verdict is unmapped when the prop is absent', () => {
    expect(showsUnmapped(undefined)).toBe(false)
  })

  it('marks a genuinely unmapped verdict', () => {
    expect(showsUnmapped(false)).toBe(true)
  })

  it('leaves a mapped verdict unmarked', () => {
    expect(showsUnmapped(true)).toBe(false)
  })
})
