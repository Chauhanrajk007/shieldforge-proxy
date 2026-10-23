import type {
  AttackClass,
  Classification,
  ClassifyRequest,
  RecommendedAction,
} from './types'

const ATTACK_CLASSES: AttackClass[] = [
  'xss',
  'sqli',
  'php_rce',
  'scanner',
  'cred_stuffing',
  'session_replay',
  'benign',
]

const ACTIONS: RecommendedAction[] = ['log', 'alert', 'rate_limit', 'challenge', 'temp_block']

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function actionFor(attackClass: AttackClass, confidence: number): RecommendedAction {
  if (attackClass === 'benign' || confidence < 0.6) return 'log'
  if (confidence >= 0.9) return 'temp_block'
  if (confidence >= 0.8) return 'challenge'
  return 'alert'
}

/**
 * Stand-in for Part 2's /classify. Deliberately dumb keyword matching so the
 * proxy can be demoed with zero external services.
 */
export function mockClassify(payload: ClassifyRequest): Classification {
  const raw = [
    payload.request.path,
    payload.request.query,
    payload.request.headers['user-agent'],
    payload.request.headers.referer,
  ].join(' ')

  let decoded = raw
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    // Keep the raw form if the payload has malformed escapes.
  }

  const haystack = `${raw} ${decoded} ${decoded.replace(/\+/g, ' ')}`.toLowerCase()

  const session = payload.session_features
  const sessionAnomaly =
    session.ip_change_count_5min >= 3 ||
    session.ua_change_count_5min >= 3 ||
    session.asn_changed

  let attackClass: AttackClass = 'benign'
  let confidence = 0.05
  let riskScore = 1

  if (/<script|javascript\s*:|onerror\s*=|onload\s*=/.test(haystack)) {
    attackClass = 'xss'
    confidence = 0.94
    riskScore = 4
  } else if (/union\s+select|or\s+1\s*=\s*1|information_schema|sleep\s*\(|benchmark\s*\(/.test(haystack)) {
    attackClass = 'sqli'
    confidence = 0.93
    riskScore = 5
  } else if (/eval\s*\(|base64_decode|shell_exec|passthru|php:\/\//.test(haystack)) {
    attackClass = 'php_rce'
    confidence = 0.96
    riskScore = 5
  } else if (/sqlmap|nikto|nmap|acunetix|nessus|dirbuster|gobuster|nuclei/.test(haystack)) {
    attackClass = 'scanner'
    confidence = 0.84
    riskScore = 3
  } else if (sessionAnomaly) {
    attackClass = 'session_replay'
    confidence = 0.78
    riskScore = 4
  }

  return {
    attack_detected: attackClass !== 'benign',
    attack_class: attackClass,
    confidence,
    risk_score: riskScore,
    action_recommended: actionFor(attackClass, confidence),
    source: 'mock',
  }
}

function normalizeRealResponse(data: unknown): Classification {
  if (!data || typeof data !== 'object') throw new Error('classify returned a non-object')
  const raw = data as Record<string, unknown>
  const attackClass = ATTACK_CLASSES.includes(raw.attack_class as AttackClass)
    ? (raw.attack_class as AttackClass)
    : 'benign'
  const action = ACTIONS.includes(raw.action_recommended as RecommendedAction)
    ? (raw.action_recommended as RecommendedAction)
    : 'log'
  const confidence = clamp(Number(raw.confidence ?? 0), 0, 1)
  const riskScore = Math.round(clamp(Number(raw.risk_score ?? 1), 1, 5))

  return {
    attack_detected: Boolean(raw.attack_detected),
    attack_class: attackClass,
    confidence,
    risk_score: riskScore,
    action_recommended: action,
    source: 'real',
  }
}

/**
 * Calls Part 2 when USE_REAL_ML=true. Any timeout/error falls back to the local
 * mock: the proxy must never fail because the ML service is down.
 */
export async function classify(payload: ClassifyRequest): Promise<Classification> {
  if (process.env.USE_REAL_ML !== 'true') return mockClassify(payload)

  const base = process.env.ML_SERVICE_URL?.replace(/\/$/, '')
  if (!base) {
    return { ...mockClassify(payload), source: 'mock-fallback', ml_error: 'ML_SERVICE_URL is not set' }
  }

  try {
    const response = await fetch(`${base}/classify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store',
      signal: AbortSignal.timeout(1500),
    })
    if (!response.ok) throw new Error(`ML service returned HTTP ${response.status}`)
    return normalizeRealResponse(await response.json())
  } catch (error) {
    return {
      ...mockClassify(payload),
      source: 'mock-fallback',
      ml_error: error instanceof Error ? error.message : 'ML call failed',
    }
  }
}
