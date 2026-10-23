type Bucket = { count: number; resetAt: number }

type RateStore = {
  buckets: Map<string, Bucket>
  lastSweep: number
}

const globalStore = globalThis as typeof globalThis & {
  __shieldRateLimit?: RateStore
}

function store(): RateStore {
  if (!globalStore.__shieldRateLimit) {
    globalStore.__shieldRateLimit = { buckets: new Map(), lastSweep: Date.now() }
  }
  return globalStore.__shieldRateLimit
}

function sweep(now: number, state: RateStore): void {
  if (now - state.lastSweep < 30_000) return
  for (const [key, bucket] of state.buckets) {
    if (bucket.resetAt <= now) state.buckets.delete(key)
  }
  state.lastSweep = now
}

/**
 * Fixed-window in-memory limiter. Good enough for a single demo instance.
 * shortcut: state is per serverless instance, use Upstash Redis when running
 * more than one instance (see README).
 */
export function checkRateLimit(
  key: string,
  max = Number(process.env.RATE_LIMIT_MAX ?? 50),
  windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 20_000),
): { allowed: boolean; remaining: number; resetAt: number; count: number } {
  const now = Date.now()
  const state = store()
  sweep(now, state)

  const safeMax = Number.isFinite(max) && max > 0 ? max : 50
  const safeWindow = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 20_000
  const bucket = state.buckets.get(key)

  if (!bucket || bucket.resetAt <= now) {
    state.buckets.set(key, { count: 1, resetAt: now + safeWindow })
    return { allowed: true, remaining: safeMax - 1, resetAt: now + safeWindow, count: 1 }
  }

  bucket.count += 1
  return {
    allowed: bucket.count <= safeMax,
    remaining: Math.max(0, safeMax - bucket.count),
    resetAt: bucket.resetAt,
    count: bucket.count,
  }
}

export function rateLimitConfig(): { max: number; windowMs: number } {
  const max = Number(process.env.RATE_LIMIT_MAX ?? 50)
  const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 20_000)
  return {
    max: Number.isFinite(max) && max > 0 ? max : 50,
    windowMs: Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 20_000,
  }
}
