import type { StoredEvent, EventStoreSnapshot } from './types'
import { listBlockedIps } from './blocklist'

const CAPACITY = 200

type Counters = EventStoreSnapshot['counters']

type State = {
  events: StoredEvent[]
  counters: Counters
}

const globalStore = globalThis as typeof globalThis & {
  __shieldEventStore?: State
}

function emptyCounters(): Counters {
  return {
    requests: 0,
    blocked: 0,
    rate_limited: 0,
    rule_hits: 0,
    ml_flagged: 0,
    findings: 0,
  }
}

function state(): State {
  if (!globalStore.__shieldEventStore) {
    globalStore.__shieldEventStore = { events: [], counters: emptyCounters() }
  }
  return globalStore.__shieldEventStore
}

/**
 * Demo event feed for the dashboard. In-memory on purpose: WRITE_TO_SUPABASE
 * is the durable path. shortcut: per-instance memory, swap for Supabase/Redis
 * when the dashboard and proxy run on multiple serverless instances.
 */
export function recordEvent(event: StoredEvent): void {
  const store = state()
  store.events.unshift(event)
  if (store.events.length > CAPACITY) store.events.length = CAPACITY

  const counters = store.counters
  counters.requests += 1
  if (event.blocked_by) counters.blocked += 1
  if (event.blocked_by === 'rate_limit') counters.rate_limited += 1
  if (event.rule_hit) counters.rule_hits += 1
  if (event.ml_attack_class !== 'benign' && event.ml_confidence >= 0.6) counters.ml_flagged += 1
  if (event.finding) counters.findings += 1
}

export async function listEvents(limit = 100): Promise<EventStoreSnapshot> {
  const store = state()
  const blockedIps = await listBlockedIps()
  return {
    events: store.events.slice(0, Math.max(0, Math.min(limit, CAPACITY))),
    counters: { ...store.counters },
    capacity: CAPACITY,
    blocked_ips: blockedIps,
    now: new Date().toISOString(),
  }
}

export function clearEvents(): void {
  const store = state()
  store.events = []
  store.counters = emptyCounters()
}
