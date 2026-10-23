import rawConfig from '@/config/origins.json'
import type { OriginConfig, Policy } from './types'

export type RawOrigin = {
  path_prefix?: string
  proxy_path?: string
  origin_url?: string
  origin_id?: string
  name?: string
  host?: string
  description?: string
  policy?: Partial<Policy>
}

type RawConfig = { origins?: RawOrigin[] } | RawOrigin[]

type RuntimeStore = { origins: OriginConfig[] }

const runtimeStore = globalThis as typeof globalThis & {
  __shieldRuntimeOrigins?: RuntimeStore
}

let cacheKey: string | null = null
let cache: OriginConfig[] = []

export function normalizeHost(value: string): string | null {
  const host = value.trim().toLowerCase()
  if (!host) return null
  // Strip a port; keep the hostname only. IPv6 literals are not supported for
  // host routing in this demo.
  const withoutPort = host.replace(/:\d+$/, '')
  if (!/^[a-z0-9.-]+$/.test(withoutPort)) return null
  if (withoutPort.startsWith('.') || withoutPort.endsWith('.')) return null
  return withoutPort
}

function normalizePrefix(value: string): string {
  const withSlash = value.startsWith('/') ? value : `/${value}`
  return withSlash.length > 1 ? withSlash.replace(/\/+$/, '') : withSlash
}

function slug(value: string): string {
  return value.replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'origin'
}

export function isPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
  return (
    host === 'localhost' ||
    host === 'metadata.google.internal' ||
    host === '0.0.0.0' ||
    host === '::1' ||
    host === '169.254.169.254' ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  )
}

export function normalizeOrigin(entry: RawOrigin, index: number): OriginConfig | null {
  const host = entry.host ? normalizeHost(entry.host) : null
  if (entry.host && !host) {
    console.warn(`[shieldforge] origin #${index} skipped: invalid host`)
    return null
  }

  const prefix = entry.path_prefix ?? entry.proxy_path ?? (host ? `/t/${slug(host)}` : undefined)
  if (!prefix) {
    console.warn(`[shieldforge] origin #${index} skipped: missing path_prefix/proxy_path`)
    return null
  }
  if (!entry.origin_url) {
    console.warn(`[shieldforge] origin ${prefix} skipped: missing origin_url`)
    return null
  }

  let parsed: URL
  try {
    parsed = new URL(entry.origin_url)
  } catch {
    console.warn(`[shieldforge] origin ${prefix} skipped: invalid origin_url`)
    return null
  }

  if (parsed.username || parsed.password) {
    console.warn(`[shieldforge] origin ${prefix} skipped: credentials are not allowed in origin_url`)
    return null
  }

  const allowPrivate = process.env.ALLOW_PRIVATE_ORIGINS === 'true'
  const privateHost = isPrivateHost(parsed.hostname)

  if (parsed.protocol !== 'https:' && !(allowPrivate && parsed.protocol === 'http:')) {
    console.warn(
      `[shieldforge] origin ${prefix} skipped: https required (set ALLOW_PRIVATE_ORIGINS=true for local http origins)`,
    )
    return null
  }

  if (privateHost && !allowPrivate) {
    console.warn(
      `[shieldforge] origin ${prefix} skipped: private/local host blocked (set ALLOW_PRIVATE_ORIGINS=true to allow)`,
    )
    return null
  }

  if (parsed.search || parsed.hash) {
    console.warn(`[shieldforge] origin ${prefix} skipped: origin_url must not contain a query/hash`)
    return null
  }

  return {
    path_prefix: normalizePrefix(prefix),
    origin_url: parsed.toString().replace(/\/$/, ''),
    origin_id: entry.origin_id ?? null,
    name: entry.name ?? (host ? `${host} (${parsed.host})` : prefix),
    host,
    description: entry.description,
    policy: entry.policy,
  }
}

function parseConfig(): OriginConfig[] {
  const envConfig = process.env.ORIGINS_JSON
  const source: RawConfig = envConfig ? (JSON.parse(envConfig) as RawConfig) : (rawConfig as RawConfig)
  const list = Array.isArray(source) ? source : (source.origins ?? [])
  return list
    .map((entry, index) => normalizeOrigin(entry, index))
    .filter((entry): entry is OriginConfig => entry !== null)
}

function runtimeOrigins(): OriginConfig[] {
  if (!runtimeStore.__shieldRuntimeOrigins) runtimeStore.__shieldRuntimeOrigins = { origins: [] }
  return runtimeStore.__shieldRuntimeOrigins.origins
}

/**
 * Origin registry. Static origins come from config/origins.json or
 * ORIGINS_JSON; origins added from the dashboard live in memory until the
 * process restarts. On Vercel use ORIGINS_JSON because each instance is fresh.
 *
 * Boundary 4's dashboard will eventually write rows to Supabase with
 * `proxy_path` + `origin_url`; both shapes and an optional `host` are accepted.
 */
export function getOrigins(): OriginConfig[] {
  const key = process.env.ORIGINS_JSON ?? '__file__'
  if (key !== cacheKey) {
    try {
      cache = parseConfig()
    } catch (error) {
      console.error('[shieldforge] failed to parse ORIGINS_JSON', error)
      cache = []
    }
    cacheKey = key
  }

  const runtime = runtimeOrigins()
  const all = [...runtime, ...cache].filter(
    (origin, index, list) =>
      list.findIndex(
        (candidate) =>
          candidate.path_prefix === origin.path_prefix ||
          (origin.host && candidate.host === origin.host),
      ) === index,
  )

  return all.sort((a, b) => b.path_prefix.length - a.path_prefix.length)
}

export function addRuntimeOrigin(entry: RawOrigin): { origin?: OriginConfig; error?: string } {
  const normalized = normalizeOrigin(entry, -1)
  if (!normalized) {
    return {
      error:
        'Origin is invalid. Use https (or enable ALLOW_PRIVATE_ORIGINS for local http), with no credentials, query or hash.',
    }
  }

  const exists = getOrigins().find(
    (origin) =>
      origin.path_prefix === normalized.path_prefix ||
      (normalized.host && origin.host === normalized.host),
  )
  if (exists) {
    return {
      error: `An origin already uses ${normalized.host ? `host ${normalized.host}` : `prefix ${normalized.path_prefix}`}.`,
    }
  }

  normalized.origin_id = normalized.origin_id ?? crypto.randomUUID()
  runtimeOrigins().push(normalized)
  return { origin: normalized }
}

export function removeRuntimeOrigin(key: string): boolean {
  const runtime = runtimeOrigins()
  const index = runtime.findIndex(
    (origin) => origin.path_prefix === key || origin.host === key,
  )
  if (index === -1) return false
  runtime.splice(index, 1)
  return true
}

export function isRuntimeOrigin(key: string): boolean {
  return runtimeOrigins().some(
    (origin) => origin.path_prefix === key || origin.host === key,
  )
}

export function matchOrigin(
  pathname: string,
  hostHeader?: string | null,
): {
  origin: OriginConfig
  upstreamPath: string
} | null {
  const host = hostHeader ? normalizeHost(hostHeader) : null
  if (host) {
    const byHost = getOrigins().find((origin) => origin.host === host)
    if (byHost) {
      // Host routing keeps the full path; the origin is mounted at its root.
      return { origin: byHost, upstreamPath: pathname }
    }
  }

  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  for (const origin of getOrigins()) {
    const prefix = origin.path_prefix
    if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
      const rest = normalized.slice(prefix.length)
      return { origin, upstreamPath: rest === '' ? '/' : rest }
    }
  }
  return null
}
