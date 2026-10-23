const SENSITIVE_KEY = /token|password|passwd|secret|session|auth|api[-_]?key|otp|csrf|jwt|bearer/i

function redactParams(search: string): string {
  if (!search) return ''
  const params = new URLSearchParams(search)
  for (const key of [...params.keys()]) {
    if (SENSITIVE_KEY.test(key)) params.set(key, '[redacted]')
  }
  return params.toString()
}

/** Redacts obvious secrets in a query string. Attack payloads stay readable. */
export function redactQuery(search: string): string {
  return redactParams(search.replace(/^\?/, ''))
}

export function redactPath(pathname: string): string {
  return pathname
}

/** Redacts the query half of a URL without touching the host/path. */
export function redactUrl(value: string): string {
  if (!value) return value
  try {
    const url = new URL(value)
    const query = redactQuery(url.search)
    return `${url.origin}${url.pathname}${query ? `?${query}` : ''}`
  } catch {
    const [path, search] = value.split('?', 2)
    const query = redactQuery(search ?? '')
    return query ? `${path}?${query}` : path
  }
}
