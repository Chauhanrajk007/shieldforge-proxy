import { NextRequest, NextResponse, type NextFetchEvent } from 'next/server'
import { isIpBlocked, blockIp } from './lib/blocklist'
import { hashSecret } from './lib/hash'
import { controlBaseUrl, isControlHost } from './lib/hosts'
import { clientIp } from './lib/ip'
import { checkRateLimit, rateLimitConfig } from './lib/rate-limit'
import { inspectRequest } from './lib/waf'
import type { WafHit } from './lib/types'

function originPrefix(pathname: string): string {
  const parts = pathname.split('/').filter(Boolean)
  if (parts[0] === 't' && parts[1]) return `/t/${parts[1]}`
  return `/${parts[0] ?? 'root'}`
}

function isAssetPath(pathname: string): boolean {
  return (
    pathname.includes('/_next/') ||
    /\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|map)$/i.test(pathname)
  )
}

function internalEvent(
  request: NextRequest,
  event: NextFetchEvent,
  input: {
    statusCode: number
    rule: WafHit
    blockedBy: 'rule' | 'rate_limit' | 'ml_block'
    durationMs: number
    ip: string
  },
): void {
  // A victim-host request must not POST to its own /api/internal/events; use
  // the control-plane origin instead.
  const url = new URL('/api/internal/events', controlBaseUrl(request.url))
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (process.env.PROXY_SHARED_SECRET) {
    headers['x-shieldforge-internal'] = process.env.PROXY_SHARED_SECRET
  }

  const cookieHeader = request.headers.get('cookie') ?? ''

  // waitUntil keeps the write alive without delaying the 403/429 response.
  event.waitUntil(
    hashSecret(cookieHeader)
      .then((cookieHash) =>
        fetch(url, {
          method: 'POST',
          headers,
          cache: 'no-store',
          signal: AbortSignal.timeout(2500),
          body: JSON.stringify({
            method: request.method,
            path: request.nextUrl.pathname,
            query: request.nextUrl.search.replace(/^\?/, ''),
            host: request.headers.get('host') ?? '',
            ip: input.ip,
            userAgent: request.headers.get('user-agent') ?? '',
            referer: request.headers.get('referer') ?? '',
            cookieHash,
            statusCode: input.statusCode,
            rule: input.rule,
            blockedBy: input.blockedBy,
            durationMs: input.durationMs,
          }),
        }),
      )
      .catch(() => {
        // The block already happened. Losing the analytics write is acceptable.
      }),
  )
}

function blockedResponse(
  request: NextRequest,
  event: NextFetchEvent,
  input: {
    statusCode: 403 | 429
    rule: WafHit
    blockedBy: 'rule' | 'rate_limit' | 'ml_block'
    message: string
    startedAt: number
    ip: string
    retryAfter?: number
  },
): NextResponse {
  internalEvent(request, event, {
    statusCode: input.statusCode,
    rule: input.rule,
    blockedBy: input.blockedBy,
    durationMs: Date.now() - input.startedAt,
    ip: input.ip,
  })

  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-shieldforge-rule': input.rule.id,
  }
  if (input.retryAfter !== undefined) headers['retry-after'] = String(input.retryAfter)

  return NextResponse.json(
    {
      error:
        input.statusCode === 429 ? 'rate_limited' : 'blocked_by_shieldforge_waf',
      message: input.message,
      rule: input.rule.id,
      category: input.rule.category,
      ...(input.retryAfter !== undefined ? { retry_after_seconds: input.retryAfter } : {}),
    },
    { status: input.statusCode, headers },
  )
}

/**
 * Edge checks: rate limit + rule-based WAF on path/query/UA + IP blocklist (Supabase).
 * Body matching happens in the Node proxy route because Edge middleware
 * cannot read request bodies.
 */
export async function middleware(request: NextRequest, event: NextFetchEvent): Promise<NextResponse> {
  const startedAt = Date.now()
  const { pathname, search } = request.nextUrl
  const host = request.headers.get('host') ?? ''
  const controlHost = isControlHost(host)

  if (controlHost) {
    if (pathname === '/') {
      return NextResponse.redirect(new URL('/dashboard', request.url))
    }
    // Control plane: dashboard, its APIs and Next's own assets are not proxied.
    if (
      pathname === '/favicon.ico' ||
      pathname.startsWith('/dashboard') ||
      pathname.startsWith('/api/') ||
      pathname.startsWith('/_next/')
    ) {
      return NextResponse.next()
    }
  }

  const ip = clientIp(request)
  const userAgent = request.headers.get('user-agent') ?? ''

  const mlBlock: WafHit = { id: 'ml-auto-block', category: 'ml_auto_block' }
  if (await isIpBlocked(ip)) {
    return blockedResponse(request, event, {
      statusCode: 403,
      rule: mlBlock,
      blockedBy: 'ml_block',
      message: 'This IP is temporarily blocked by the enforce policy.',
      startedAt,
      ip,
    })
  }

  const waf = inspectRequest({ path: pathname, query: search, userAgent })
  if (waf.hit) {
    return blockedResponse(request, event, {
      statusCode: 403,
      rule: waf.rule,
      blockedBy: 'rule',
      message: `Request blocked by the rule-based WAF (${waf.rule.id}).`,
      startedAt,
      ip,
    })
  }

  // Assets are proxied too (a victim's /_next chunks must reach the victim),
  // but they should not consume the API rate-limit budget.
  if (!isAssetPath(pathname)) {
    const { max, windowMs } = rateLimitConfig()
    const rateKey = controlHost ? `${ip}:${originPrefix(pathname)}` : `${ip}:${host}`
    const limit = checkRateLimit(rateKey, max, windowMs)
    if (!limit.allowed) {
      const retryAfter = Math.max(1, Math.ceil((limit.resetAt - Date.now()) / 1000))
      return blockedResponse(request, event, {
        statusCode: 429,
        rule: { id: 'rate-limit', category: 'rate_limit' },
        blockedBy: 'rate_limit',
        message: `Too many requests. Retry in ${retryAfter}s.`,
        startedAt,
        ip,
        retryAfter,
      })
    }
  }

  if (controlHost) return NextResponse.next()

  // Host-based victim routing. Rewriting keeps the victim's own /api/* and
  // /_next/* paths intact instead of colliding with the control plane.
  const target = request.nextUrl.clone()
  target.pathname = pathname === '/' ? '/_proxy' : `/_proxy${pathname}`
  return NextResponse.rewrite(target)
}

export const config = {
  // Everything goes through middleware so victim-host assets and APIs can be
  // proxied. The control host is filtered inside the function.
  matcher: ['/:path*'],
}
