export const SECURITY_HEADERS: Array<{ header: string; label: string }> = [
  { header: 'content-security-policy', label: 'Content-Security-Policy' },
  { header: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { header: 'x-frame-options', label: 'X-Frame-Options' },
  { header: 'strict-transport-security', label: 'Strict-Transport-Security' },
  { header: 'referrer-policy', label: 'Referrer-Policy' },
  { header: 'permissions-policy', label: 'Permissions-Policy' },
]

export function missingSecurityHeaders(headers: Headers): string[] {
  return SECURITY_HEADERS.filter(({ header }) => !headers.get(header)).map(({ header }) => header)
}
