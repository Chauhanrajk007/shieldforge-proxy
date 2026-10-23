import type { CookieInspection, SetCookieFlags } from './types'

function flagsFor(cookie: string): SetCookieFlags {
  const lower = cookie.toLowerCase()
  const sameSiteMatch = lower.match(/;\s*samesite=([^;]+)/)
  return {
    httponly: /;\s*httponly\b/.test(lower),
    secure: /;\s*secure\b/.test(lower),
    samesite: sameSiteMatch ? sameSiteMatch[1].trim() : null,
  }
}

/**
 * Reports ONLY flags. Cookie names and values never leave this function.
 * Boundary 1 / Boundary 2 both require this.
 */
export function getSetCookieHeaders(headers: Headers): string[] {
  const withSetter = headers as Headers & { getSetCookie?: () => string[] }
  const fromRuntime = withSetter.getSetCookie?.() ?? []
  if (fromRuntime.length > 0) return fromRuntime

  const combined = headers.get('set-cookie')
  // Expires contains a comma, so only split on commas that start a new
  // `name=value` pair.
  return combined ? combined.split(/,(?=\s*[^;,=\s]+=)/) : []
}

export function inspectCookies(headers: Headers): CookieInspection {
  const cookies = getSetCookieHeaders(headers)
    .filter(Boolean)
    .map(flagsFor)
  return {
    count: cookies.length,
    flags: cookies[0] ?? null,
    cookies,
  }
}

/**
 * Makes an origin cookie usable on the proxy host: drops Domain (it points at
 * the origin) and scopes Path under the proxy prefix. The value is copied but
 * never logged.
 */
export function rewriteSetCookie(cookie: string, prefix: string): string {
  const base = prefix.replace(/\/$/, '')
  const parts = cookie
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
  const out: string[] = []
  let hasPath = false

  for (const part of parts) {
    const separator = part.indexOf('=')
    const name = (separator === -1 ? part : part.slice(0, separator)).toLowerCase()
    if (name === 'domain') continue
    if (name === 'path') {
      const value = separator === -1 ? '/' : part.slice(separator + 1) || '/'
      const scoped = value === '/' ? base || '/' : `${base}${value.startsWith('/') ? value : `/${value}`}`
      out.push(`Path=${scoped}`)
      hasPath = true
      continue
    }
    out.push(part)
  }

  if (!hasPath) out.push(`Path=${base || '/'}`)
  return out.join('; ')
}
