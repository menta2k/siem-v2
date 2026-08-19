/**
 * Turns any thrown value into something safe to show a user.
 *
 * The backend already separates operator detail from caller-facing text, so the
 * message it returns is safe to display verbatim. Anything else — a network
 * failure, a thrown string — gets a generic message rather than being echoed,
 * since an unrecognized error could carry internal detail.
 */
export function toDisplayMessage(err: unknown, fallback = 'The request could not be completed.'): string {
  if (err && typeof err === 'object') {
    const data = (err as { data?: { message?: string } }).data
    if (data?.message) return data.message

    const status = (err as { statusCode?: number }).statusCode
    if (status === 401) return 'Your session is not authenticated.'
    if (status === 404) return 'Not found.'
    if (status === 429) return 'Too many requests — please wait a moment.'
    if (status === 503) return 'The service is temporarily unavailable.'
  }
  return fallback
}
