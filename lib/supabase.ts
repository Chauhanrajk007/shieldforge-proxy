import type { Policy, RecommendedAction, StoredEvent } from './types'

function supabaseConfig(): { url: string; key: string } | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) return null
  return { url: url.replace(/\/$/, ''), key }
}

export function eventRow(event: StoredEvent) {
  return {
    id: event.id,
    origin_id: event.origin_id,
    method: event.method,
    path: event.path,
    ip: event.ip,
    user_agent: event.user_agent,
    status_code: event.status_code,
    rule_hit: event.rule_hit,
    features: event.features,
    ml_attack_class: event.ml_attack_class,
    ml_confidence: event.ml_confidence,
    ml_risk_score: event.ml_risk_score,
  }
}

async function insert(
  table: string,
  row: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const config = supabaseConfig()
  if (!config) throw new Error('Supabase URL or service-role key is missing')

  const response = await fetch(`${config.url}/rest/v1/${table}`, {
    method: 'POST',
    headers: {
      apikey: config.key,
      authorization: `Bearer ${config.key}`,
      'content-type': 'application/json',
      prefer: 'return=representation',
    },
    body: JSON.stringify(row),
    cache: 'no-store',
    signal: AbortSignal.timeout(4000),
  })

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300)
    throw new Error(`${table} insert failed (HTTP ${response.status}): ${detail}`)
  }

  const data = (await response.json()) as Record<string, unknown>[]
  return data[0] ?? null
}

/**
 * Boundary 2, live mode. Async and best-effort: a Supabase outage or a schema
 * mismatch must never surface to the visitor.
 */
export async function writeEventToSupabase(
  event: StoredEvent,
  action: RecommendedAction,
  mode: Policy['mode'],
): Promise<void> {
  if (!supabaseConfig()) {
    console.warn('[shieldforge] WRITE_TO_SUPABASE=true but Supabase env vars are missing; skipping write')
    return
  }

  await insert('events', eventRow(event))

  if (!event.finding) return

  const finding = await insert('findings', {
    origin_id: event.finding.origin_id,
    event_id: event.id,
    severity: event.finding.severity,
    category: event.finding.category,
    title: event.finding.title,
    evidence: { ...event.finding.evidence, policy_mode: mode },
    status: 'open',
  })
  if (!finding) return

  if (!event.incident) return

  await insert('incidents', {
    finding_id: finding.id,
    action_taken: action,
    confidence: event.incident.confidence,
    resolved: false,
  })
}
