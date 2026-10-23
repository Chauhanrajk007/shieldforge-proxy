/**
 * Prefer platform-injected headers. A raw client can spoof x-forwarded-for;
 * Vercel's x-vercel-forwarded-for is the trustworthy one in production.
 * shortcut: no trusted-proxy config, add it when moving off Vercel.
 */
export function clientIp(request: Request): string {
  const vercel = request.headers.get('x-vercel-forwarded-for')
  if (vercel) return vercel.split(',')[0]!.trim()

  const real = request.headers.get('x-real-ip')
  if (real) return real.trim()

  const forwarded = request.headers.get('x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0]!.trim()

  return 'unknown'
}
