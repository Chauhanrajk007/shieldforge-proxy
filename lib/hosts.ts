function entries(): string[] {
  const configured = (process.env.CONTROL_HOSTS ?? '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)

  const defaults = ['localhost', '127.0.0.1', '[::1]']
  const vercel = [process.env.VERCEL_URL, process.env.VERCEL_PROJECT_PRODUCTION_URL]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase())

  return [...new Set([...configured, ...defaults, ...vercel])]
}

/**
 * The control plane (dashboard + its APIs) is only served on these hosts.
 * Every other Host is treated as a victim origin and proxied through
 * /_proxy, which is what lets a victim keep its own /api and /_next paths.
 */
export function isControlHost(hostHeader: string): boolean {
  const host = hostHeader.toLowerCase()
  const hostname = host.replace(/:\d+$/, '')
  return entries().some((entry) => host === entry || hostname === entry)
}

/**
 * Absolute control-plane base used by middleware for the internal event sink.
 * A victim-host request cannot POST to /api/internal/events on its own host,
 * because that path belongs to the victim.
 */
export function controlBaseUrl(requestUrl: string): string {
  if (process.env.PROXY_CONTROL_ORIGIN) {
    return process.env.PROXY_CONTROL_ORIGIN.replace(/\/$/, '')
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`
  }
  const url = new URL(requestUrl)
  if (isControlHost(url.host)) return url.origin
  return 'http://localhost:3000'
}
