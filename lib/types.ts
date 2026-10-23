export type PolicyMode = 'shadow' | 'enforce'

export type Policy = {
  auto_block_threshold: number
  alert_threshold: number
  mode: PolicyMode
}

export type OriginConfig = {
  path_prefix: string
  origin_url: string
  origin_id: string | null
  name: string
  /** Optional host-based route, e.g. victim.local. Host matching wins over path matching. */
  host?: string | null
  description?: string
  policy?: Partial<Policy>
}

export type WafRule = {
  id: string
  category: string
  pattern: RegExp
}

export type WafHit = {
  id: string
  category: string
}

export type WafResult =
  | { hit: false }
  | { hit: true; rule: WafHit }

export type AttackClass =
  | 'xss'
  | 'sqli'
  | 'php_rce'
  | 'scanner'
  | 'cred_stuffing'
  | 'session_replay'
  | 'benign'

export type RecommendedAction =
  | 'log'
  | 'alert'
  | 'rate_limit'
  | 'challenge'
  | 'temp_block'

export type Classification = {
  attack_detected: boolean
  attack_class: AttackClass
  confidence: number
  risk_score: number
  action_recommended: RecommendedAction
  /** Internal only — never sent over Boundary 1. */
  source: 'mock' | 'real' | 'mock-fallback'
  /** Internal only — why the real call failed, when it did. */
  ml_error?: string
}

export type SetCookieFlags = {
  httponly: boolean
  secure: boolean
  samesite: string | null
}

export type CookieInspection = {
  count: number
  flags: SetCookieFlags | null
  cookies: SetCookieFlags[]
}

export type SessionFeatures = {
  session_token_hash: string | null
  ip_change_count_5min: number
  ua_change_count_5min: number
  asn_changed: boolean
}

/** Boundary 1 request body. */
export type ClassifyRequest = {
  request: {
    method: string
    path: string
    query: string
    headers: { 'user-agent': string; referer: string }
    ip: string
  }
  response_meta: {
    status_code: number
    set_cookie_flags: SetCookieFlags | null
    content_length: number
  }
  session_features: SessionFeatures
}

export type FindingDraft = {
  origin_id: string | null
  event_id?: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: string
  title: string
  evidence: Record<string, unknown>
  status: 'open'
}

export type IncidentDraft = {
  finding_id?: string
  action_taken: RecommendedAction
  confidence: number
  resolved: boolean
}

export type EmitInput = {
  origin: OriginConfig | null
  method: string
  path: string
  query: string
  ip: string
  userAgent: string
  referer: string
  cookieHash?: string | null
  statusCode: number
  durationMs: number
  ruleHit: WafHit | null
  blockedBy: 'rule' | 'rate_limit' | 'ml_block' | null
  cookies: CookieInspection | null
  missingSecurityHeaders: string[]
  contentLength: number
  upstreamError?: string | null
}

export type StoredEvent = {
  id: string
  ts: string
  origin_id: string | null
  origin_prefix: string | null
  method: string
  path: string
  query: string
  ip: string
  user_agent: string
  status_code: number
  duration_ms: number
  rule_hit: string | null
  rule_category: string | null
  blocked_by: EmitInput['blockedBy']
  features: ClassifyRequest
  set_cookie_flags: SetCookieFlags | null
  cookie_count: number
  cookies: SetCookieFlags[]
  missing_security_headers: string[]
  ml_attack_class: string
  ml_confidence: number
  ml_risk_score: number
  ml_action_recommended: RecommendedAction
  ml_source: Classification['source']
  ml_error: string | null
  finding: FindingDraft | null
  incident: IncidentDraft | null
  upstream_error: string | null
}

export type EventStoreSnapshot = {
  events: StoredEvent[]
  counters: {
    requests: number
    blocked: number
    rate_limited: number
    rule_hits: number
    ml_flagged: number
    findings: number
  }
  capacity: number
  blocked_ips: Array<{ ip: string; expiresAt: number }>
  now: string
}
