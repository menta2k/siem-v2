// Shared bits for the WAF-migration pages.

export interface WafRange { from: string, to: string }

// Windows decisions ride on accumulated agreement, not the last hour, so the
// default is a week (v1 parity).
export const WAF_RANGES = [
  { title: 'Last hour', hours: 1 },
  { title: 'Last 24 hours', hours: 24 },
  { title: 'Last 3 days', hours: 72 },
  { title: 'Last 7 days', hours: 168 },
  { title: 'Last 30 days', hours: 720 },
]
export const DEFAULT_WAF_HOURS = 168

/** A verdict word to a Vuetify colour, consistent with VerdictBadge. */
export function wafVerdictColor(verdict: string): string {
  switch (verdict) {
    case 'blocked': return 'error'
    case 'monitored': return 'info'
    case 'allowed': return 'success'
    default: return 'secondary'
  }
}

/**
 * Cloudflare's WAF attack score band. THE SCALE IS INVERTED: 1 is certainly an
 * attack, 100 certainly clean — the opposite of every other score. Always shown
 * with a word so the number is never misread. 0/undefined means "not scored".
 */
export function attackBand(score?: number): { color: string, label: string } | null {
  if (score === undefined || score <= 0) return null
  if (score <= 20) return { color: 'error', label: 'attack' }
  if (score <= 50) return { color: 'warning', label: 'suspicious' }
  if (score <= 80) return { color: 'info', label: 'leaning clean' }
  return { color: 'success', label: 'clean' }
}

/** The attack class a CRS rule belongs to, read off its own tags. */
export function crsCategory(tags?: string[]): string {
  const t = (tags ?? []).find((x) => x.startsWith('attack-'))
  return t ? t.replace('attack-', '').toUpperCase() : ''
}

/** CRS severity to a Vuetify colour. */
export function crsSeverityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return 'error'
    case 'ERROR': return 'error'
    case 'WARNING': return 'warning'
    case 'NOTICE': return 'info'
    default: return 'secondary'
  }
}

/** A reading to a colour + human label. */
export function readingLabel(reading: string): { color: string, text: string } {
  switch (reading) {
    case 'ready': return { color: 'success', text: 'Ready to enforce' }
    case 'disputed': return { color: 'warning', text: 'Disputed' }
    case 'false_positive': return { color: 'error', text: 'Likely false positive' }
    default: return { color: 'secondary', text: 'Insufficient evidence' }
  }
}
