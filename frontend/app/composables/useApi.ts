/**
 * API access.
 *
 * The frontend never talks to the log store directly and never constructs a
 * query: it sends typed parameters and the backend compiles them with the
 * tenant injected server-side. That is what makes cross-tenant access
 * inexpressible rather than merely refused.
 */
export interface Verdict {
  action: string
  terminating: boolean
  rule_id?: string
  rule_name?: string
  category?: string
  score?: number
  mapped: boolean
}

export interface FlowEvent {
  event_id: string
  provider: string
  layer: string
  event_time: string
  received_at: string
  verdict: Verdict
  data_quality_flags?: string[]
  client?: { ip?: string; country?: string; user_agent?: string }
  request?: { method?: string; host?: string; path?: string }
  response?: { status?: number; duration_ms?: number }
}

export interface Flow {
  flow_id: string
  correlation_key: string
  events: FlowEvent[]
  layers_present: string[]
  layers_missing: string[]
  completeness: 'complete' | 'partial' | 'ambiguous'
  correlation_method: string
  correlation_confidence: number
  bridged: boolean
  effective_outcome: string
  terminating_layer?: string
  first_seen: string
  data_quality_flags?: string[]
  client: { ip?: string; country?: string; user_agent?: string }
  request: { method?: string; host?: string; path?: string }
}

export interface FlowSearch {
  from?: string
  to?: string
  client_ip?: string
  host?: string
  path_prefix?: string
  method?: string
  status?: number
  action?: string
  provider?: string
  completeness?: string
  user_agent?: string
  rule_id?: string
  country?: string
  asn?: number
  /** The definitive identifier: every layer that saw the request reports it. */
  ray_id?: string
  /** F5's own reference — what an operator quotes to F5 support. */
  support_id?: string
  correlation_method?: string
  bridged?: boolean
  min_layers?: number
  max_layers?: number
  quality_flag?: string
  limit?: number
}

export function useApi() {
  const config = useRuntimeConfig()
  const base = config.public.apiBase
  // The identity is the bearer credential in this development build; a real
  // deployment substitutes an identity provider here without changing anything
  // else, because the tenant is resolved server-side from whoever this is.
  //
  // Persisted so a page reload keeps the chosen identity. In a real deployment
  // this is replaced by the identity provider's session; what must not change is
  // that the TENANT is resolved server-side from whoever this turns out to be.
  const identity = useState<string>('identity', () => {
    if (import.meta.client) {
      return sessionStorage.getItem('siem-identity') ?? 'analyst@acme.example.com'
    }
    return 'analyst@acme.example.com'
  })

  if (import.meta.client) {
    watch(identity, (v) => sessionStorage.setItem('siem-identity', v))
  }

  // A real session's access token always wins; the dev identity string is the
  // fallback that keeps local browsing working (the server honours it only when
  // SIEM_DEV_IDENTITIES is set).
  const accessToken = useState<string | null>('auth-access', () => null)

  function headers() {
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken.value ?? identity.value}`,
    }
  }

  async function searchFlows(params: FlowSearch): Promise<{ flows: Flow[]; count: number }> {
    return await $fetch(`${base}/flows/search`, {
      method: 'POST', headers: headers(), body: params,
    })
  }

  async function getFlow(flowId: string): Promise<Flow> {
    return await $fetch(`${base}/flows/${encodeURIComponent(flowId)}`, { headers: headers() })
  }

  async function evaluate(body: Record<string, unknown>) {
    return await $fetch(`${base}/evaluations`, { method: 'POST', headers: headers(), body })
  }

  async function collectionHealth() {
    return await $fetch(`${base}/health/collection`, { headers: headers() })
  }

  return { identity, headers, searchFlows, getFlow, evaluate, collectionHealth }
}

/** Human label for a layer. */
export function layerLabel(layer: string): string {
  return ({
    edge: 'Cloudflare (edge)',
    bot_management: 'DataDome (bot)',
    app_firewall: 'F5 ASM (WAF)',
    origin: 'nginx (origin)',
  } as Record<string, string>)[layer] ?? layer
}
