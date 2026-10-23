import { randomUUID } from 'node:crypto'
import { blockIp } from './blocklist'
import { recordEvent } from './event-store'
import { classify } from './ml'
import { getPolicy } from './policies'
import { redactPath, redactQuery, redactUrl } from './redact'
import { eventRow, writeEventToSupabase } from './supabase'
import type {
  Classification,
  ClassifyRequest,
  EmitInput,
  FindingDraft,
  IncidentDraft,
  Policy,
  RecommendedAction,
  StoredEvent,
} from './types'

function severityFor(category: string, confidence: number): FindingDraft['severity'] {
  if (category === 'scanner' || category === 'rate_limit') return 'medium'
  if (category === 'session_replay' || category === 'cred_stuffing') return 'high'
  if (confidence >= 0.95) return 'critical'
  return 'high'
}

function actionTaken(
  ruleHit: EmitInput['ruleHit'],
  classification: Classification,
  policy: Policy,
  hasIncident: boolean,
): RecommendedAction {
  if (ruleHit) return ruleHit.category === 'rate_limit' ? 'rate_limit' : 'temp_block'
  if (!hasIncident) return 'log'
  if (policy.mode === 'enforce') return 'temp_block'
  return classification.confidence >= policy.auto_block_threshold ? 'alert' : classification.action_recommended
}

function buildFinding(
  input: EmitInput,
  classification: Classification,
  policy: Policy,
  action: RecommendedAction,
): FindingDraft | null {
  if (input.ruleHit) {
    return {
      origin_id: input.origin?.origin_id ?? null,
      severity: severityFor(input.ruleHit.category, classification.confidence),
      category: input.ruleHit.category,
      title:
        input.ruleHit.category === 'rate_limit'
          ? 'Rate limit exceeded'
          : `Blocked ${input.ruleHit.category} payload (${input.ruleHit.id})`,
      evidence: {
        rule: input.ruleHit.id,
        blocked_by: input.blockedBy,
        path: redactPath(input.path),
        query: redactQuery(input.query),
        ip: input.ip,
        policy_mode: policy.mode,
      },
      status: 'open',
    }
  }

  if (!classification.attack_detected || classification.confidence < policy.alert_threshold) {
    if (input.cookies?.cookies.some((cookie) => !cookie.httponly)) {
      return {
        origin_id: input.origin?.origin_id ?? null,
        severity: 'medium',
        category: 'weak_cookie',
        title: 'Response set a cookie without HttpOnly',
        evidence: {
          set_cookie_flags: input.cookies.flags,
          cookie_count: input.cookies.count,
          path: redactPath(input.path),
          policy_mode: policy.mode,
        },
        status: 'open',
      }
    }
    return null
  }

  return {
    origin_id: input.origin?.origin_id ?? null,
    severity: severityFor(classification.attack_class, classification.confidence),
    category: classification.attack_class,
    title: `ML detected ${classification.attack_class} with ${Math.round(classification.confidence * 100)}% confidence`,
    evidence: {
      confidence: classification.confidence,
      risk_score: classification.risk_score,
      recommended: classification.action_recommended,
      action_taken: action,
      path: redactPath(input.path),
      query: redactQuery(input.query),
      ip: input.ip,
      policy_mode: policy.mode,
    },
    status: 'open',
  }
}

function cookieSummary(input: EmitInput): string {
  if (!input.cookies || input.cookies.count === 0) return 'cookies=0'
  const flags = input.cookies.flags
  return `cookies=${input.cookies.count} httponly=${flags?.httponly ?? false} secure=${
    flags?.secure ?? false
  } samesite=${flags?.samesite ?? 'none'}`
}

/**
 * Boundary 1 + Boundary 2. Called from `after()` in the proxy route, or from
 * the internal events route for blocks that happened in middleware. It never
 * throws and never holds the visitor's response open.
 */
export async function emitEvent(input: EmitInput): Promise<void> {
  const policy = getPolicy(input.origin)

  const payload: ClassifyRequest = {
    request: {
      method: input.method,
      path: redactPath(input.path),
      query: redactQuery(input.query),
      headers: {
        'user-agent': input.userAgent.slice(0, 300),
        referer: redactUrl(input.referer),
      },
      ip: input.ip,
    },
    response_meta: {
      status_code: input.statusCode,
      set_cookie_flags: input.cookies?.flags ?? null,
      content_length: input.contentLength,
    },
    session_features: {
      session_token_hash: input.cookieHash || null,
      ip_change_count_5min: 0,
      ua_change_count_5min: 0,
      asn_changed: false,
    },
  }

  let classification: Classification
  try {
    classification = await classify(payload)
  } catch (error) {
    // classify() already fails open; this is the belt-and-braces path.
    classification = {
      attack_detected: false,
      attack_class: 'benign',
      confidence: 0,
      risk_score: 1,
      action_recommended: 'log',
      source: 'mock-fallback',
      ml_error: error instanceof Error ? error.message : 'classifier crashed',
    }
  }

  const hasIncident =
    Boolean(input.ruleHit) ||
    (classification.attack_detected && classification.confidence >= policy.auto_block_threshold)
  const action = actionTaken(input.ruleHit, classification, policy, hasIncident)

  const finding = buildFinding(input, classification, policy, action)
  const incident: IncidentDraft | null =
    finding && hasIncident
      ? {
          action_taken: action,
          // A rule hit is a certainty; the ML number is only meaningful when
          // ML was the reason for the finding/incident.
          confidence: input.ruleHit ? 1 : classification.confidence,
          resolved: false,
        }
      : null

  const event: StoredEvent = {
    id: randomUUID(),
    ts: new Date().toISOString(),
    origin_id: input.origin?.origin_id ?? null,
    origin_prefix: input.origin?.path_prefix ?? null,
    method: input.method,
    path: redactPath(input.path),
    query: redactQuery(input.query),
    ip: input.ip,
    user_agent: input.userAgent,
    status_code: input.statusCode,
    duration_ms: input.durationMs,
    rule_hit: input.ruleHit?.id ?? null,
    rule_category: input.ruleHit?.category ?? null,
    blocked_by: input.blockedBy,
    features: payload,
    set_cookie_flags: input.cookies?.flags ?? null,
    cookie_count: input.cookies?.count ?? 0,
    cookies: input.cookies?.cookies ?? [],
    missing_security_headers: input.missingSecurityHeaders,
    ml_attack_class: classification.attack_class,
    ml_confidence: classification.confidence,
    ml_risk_score: classification.risk_score,
    ml_action_recommended: classification.action_recommended,
    ml_source: classification.source,
    ml_error: classification.ml_error ?? null,
    finding,
    incident,
    upstream_error: input.upstreamError ?? null,
  }

  // Enforce mode acts on the *next* request: this one already has a response.
  if (
    classification.attack_detected &&
    classification.confidence >= policy.auto_block_threshold &&
    policy.mode === 'enforce'
  ) {
    await blockIp(input.ip)
  }

  recordEvent(event)

  const blocked = input.blockedBy ? 'BLOCK ' : ''
  console.log(
    `[shieldforge] ${blocked}${input.statusCode} ${input.method} ${input.path} ` +
      `rule=${event.rule_hit ?? '-'} ml=${classification.attack_class}:${classification.confidence} ` +
      `${cookieSummary(input)} missing_headers=${input.missingSecurityHeaders.length}` +
      (classification.ml_error ? ` ml_error=${classification.ml_error}` : ''),
  )

  if (event.cookie_count > 0 && event.set_cookie_flags && !event.set_cookie_flags.httponly) {
    // Flags only. The cookie's name and value are never available here.
    console.warn(
      `[shieldforge] weak cookie on ${input.path}: HttpOnly is missing` +
        (event.set_cookie_flags.secure ? '' : ', Secure is missing') +
        (event.set_cookie_flags.samesite ? '' : ', SameSite is missing'),
    )
  }

  if (process.env.WRITE_TO_SUPABASE === 'true') {
    try {
      await writeEventToSupabase(event, action, policy.mode)
    } catch (error) {
      console.error(
        '[shieldforge] Supabase write failed (response already sent)',
        error instanceof Error ? error.message : error,
      )
    }
  } else {
    console.log(
      '[shieldforge] mock DB write (WRITE_TO_SUPABASE=false)',
      JSON.stringify({ event: eventRow(event), finding: event.finding, incident: event.incident }, null, 2),
    )
  }
}
