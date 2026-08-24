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

/** A reading to a colour + human label. */
export function readingLabel(reading: string): { color: string, text: string } {
  switch (reading) {
    case 'ready': return { color: 'success', text: 'Ready to enforce' }
    case 'disputed': return { color: 'warning', text: 'Disputed' }
    case 'false_positive': return { color: 'error', text: 'Likely false positive' }
    default: return { color: 'secondary', text: 'Insufficient evidence' }
  }
}
