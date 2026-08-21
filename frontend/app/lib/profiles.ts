/**
 * Display logic for traffic profiles, kept out of the component so the rules
 * are unit-testable (the repo's pattern: logic in lib/, rendering in pages/).
 */

/** One segment of a path template, ready to render. */
export interface TemplateSegment {
  text: string
  isParam: boolean
}

/**
 * Split "/job/{int}/apply" into renderable segments. Parameter tokens are
 * marked so the template reads as a route, not a literal URL.
 */
export function templateSegments(template: string): TemplateSegment[] {
  const parts = template.split('/').filter(p => p !== '')
  if (!parts.length) return [{ text: '/', isParam: false }]
  return parts.map(p => ({
    text: p,
    isParam: p.length > 2 && p.startsWith('{') && p.endsWith('}'),
  }))
}

/** Vuetify color per inferred parameter type — one hue family per "certainty band". */
export function typeColor(type: string): string {
  switch (type) {
    case 'int': case 'float': return 'teal'
    case 'bool': return 'green'
    case 'uuid': return 'indigo'
    case 'hex': return 'deep-purple'
    case 'date': return 'cyan'
    case 'email': return 'orange'
    case 'ipv4': case 'ipv6': return 'blue'
    case 'json': return 'purple'
    case 'alnum': return 'blue-grey'
    case 'var': return 'brown'
    case 'freetext': return 'grey'
    default: return 'grey'
  }
}

export function methodColor(method: string): string {
  switch (method) {
    case 'GET': return 'primary'
    case 'POST': return 'success'
    case 'PUT': case 'PATCH': return 'warning'
    case 'DELETE': return 'error'
    default: return 'grey'
  }
}

/** Bucket an exact status ("404") into its class for the mix bar. */
export function statusClass(status: string): '2xx' | '3xx' | '4xx' | '5xx' | 'other' {
  const c = status.charAt(0)
  if (c === '2') return '2xx'
  if (c === '3') return '3xx'
  if (c === '4') return '4xx'
  if (c === '5') return '5xx'
  return 'other'
}

export const STATUS_CLASS_COLORS: Record<string, string> = {
  '2xx': '#4caf50', '3xx': '#2196f3', '4xx': '#ff9800', '5xx': '#f44336', other: '#9e9e9e',
}

export interface MixSlice {
  cls: string
  count: number
  share: number
  color: string
}

/**
 * Reduce a {"200": 9541, "404": 12} mix into ordered class slices for a
 * stacked bar. Classes render in severity order so the red is always at the
 * same end.
 */
export function statusMixSlices(mix: Record<string, number> | null | undefined): MixSlice[] {
  if (!mix) return []
  const byClass = new Map<string, number>()
  let total = 0
  for (const [status, count] of Object.entries(mix)) {
    const cls = statusClass(status)
    byClass.set(cls, (byClass.get(cls) ?? 0) + count)
    total += count
  }
  if (total === 0) return []
  const order = ['2xx', '3xx', '4xx', '5xx', 'other']
  return order
    .filter(cls => byClass.has(cls))
    .map(cls => ({
      cls,
      count: byClass.get(cls)!,
      share: byClass.get(cls)! / total,
      color: STATUS_CLASS_COLORS[cls]!,
    }))
}

/**
 * Aggregate an endpoint's parameters by inferred type for the composition
 * bar — the fastest way to spot an endpoint that is all-freetext.
 */
export function typeComposition(params: Array<{ inferred_type: string }>): MixSlice[] {
  const byType = new Map<string, number>()
  for (const p of params) {
    byType.set(p.inferred_type, (byType.get(p.inferred_type) ?? 0) + 1)
  }
  const total = params.length
  if (!total) return []
  return [...byType.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([type, count]) => ({
      cls: type, count, share: count / total, color: '',
    }))
}

/**
 * A structural ceiling renders as a number when measured and as "not captured"
 * when the provider never shipped the fact. null is NOT zero — presenting an
 * absent measurement as 0 would turn a coverage gap into a false claim.
 */
export function ceiling(value: number | null | undefined, unit = ''): string {
  if (value === null || value === undefined) return 'not captured'
  return unit === 'B' ? bytes(value) : `${value}${unit}`
}

export function bytes(n: number): string {
  if (!n || n <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

/** Compact large counts for the host strip: 12841 → "12.8k". */
export function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 10_000) return `${Math.round(n / 1000)}k`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}
