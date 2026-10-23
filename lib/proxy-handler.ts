/**
 * Shared proxy data plane used by both routing modes:
 *   /t/<name>   path-prefix mode (control host)
 *   /_proxy/*   host mode (victim host rewritten by middleware)
 *
 * TRADEOFF, stated on purpose: Vercel serverless has cold starts and an
 * execution-time limit, and this route buffers request bodies for WAF
 * inspection. It is a hackathon demo data plane, not a 24/7 production WAF.
 * A production deployment would run this as a dedicated proxy process (or on
 * Cloudflare/nginx) with body streaming and a distributed rate limiter.
 *
 * Latency contract: the visitor gets the upstream response immediately. The
 * ML classification and Supabase writes run in `after()` and never block the
 * response. TLS certificates are verified by the platform fetch.
 */
import { after } from 'next/server'
import { isIpBlocked, blockIp } from './blocklist'
import { getSetCookieHeaders, inspectCookies, rewriteSetCookie } from './cookies'
import { emitEvent } from './emit'
import { hashSecret } from './hash'
import { clientIp } from './ip'
import { missingSecurityHeaders } from './security-headers'
import type { CookieInspection, EmitInput, OriginConfig, WafHit } from './types'
import { inspectRequest } from './waf'

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

export type ProxyTarget = {
  origin: OriginConfig
  /** Path forwarded to the origin, after the registered prefix is removed. */
  upstreamPath: string
  /** Path the visitor requested, used for WAF/events. */
  publicPath: string
  /** Public mount point. Empty in host mode. */
  publicPrefix: string
  hostMode: boolean
}

function queryOf(url: URL): string {
  return url.search.replace(/^\?/, '')
}

function json(body: unknown, status: number, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  })
}

function buildUpstreamUrl(origin: OriginConfig, upstreamPath: string, search: string): URL {
  const target = new URL(origin.origin_url)
  const basePath = target.pathname.replace(/\/$/, '')
  const joined = `${basePath}${upstreamPath}`.replace(/\/{2,}/g, '/')
  target.pathname = joined.startsWith('/') ? joined : `/${joined}`
  target.search = search
  return target
}

function rewriteLocation(
  location: string,
  origin: OriginConfig,
  upstreamUrl: URL,
  publicPrefix: string,
): string {
  try {
    const absolute = new URL(location, upstreamUrl)
    const originUrl = new URL(origin.origin_url)
    if (absolute.origin !== originUrl.origin) return location

    const basePath = originUrl.pathname.replace(/\/$/, '')
    const rest = absolute.pathname.startsWith(basePath)
      ? absolute.pathname.slice(basePath.length)
      : absolute.pathname
    const proxyRest = rest === '' ? '/' : rest.startsWith('/') ? rest : `/${rest}`

    if (!publicPrefix) return `${proxyRest}${absolute.search}${absolute.hash}`
    return `${publicPrefix.replace(/\/$/, '')}${proxyRest}${absolute.search}${absolute.hash}`
  } catch {
    return location
  }
}

async function emitAfterResponse(
  input: Omit<EmitInput, 'cookieHash'>,
  cookieHeader: string,
): Promise<void> {
  await emitEvent({ ...input, cookieHash: await hashSecret(cookieHeader) })
}

function blocked(
  input: {
    status: number
    rule: WafHit
    blockedBy: 'rule' | 'ml_block'
    message: string
    origin: OriginConfig | null
    method: string
    path: string
    query: string
    ip: string
    userAgent: string
    referer: string
    cookieHeader: string
    startedAt: number
    request: Request
  },
): Response {
  const body: EmitInput = {
    origin: input.origin,
    method: input.method,
    path: input.path,
    query: input.query,
    ip: input.ip,
    userAgent: input.userAgent,
    referer: input.referer,
    statusCode: input.status,
    durationMs: Date.now() - input.startedAt,
    ruleHit: input.rule,
    blockedBy: input.blockedBy,
    cookies: null,
    missingSecurityHeaders: [],
    contentLength: 0,
  }

  after(() => emitAfterResponse(body, input.cookieHeader))

  const accept = input.request.headers.get('accept') ?? ''
  const wantsHtml = accept.includes('text/html')
  const payload = {
    error: 'blocked_by_shieldforge_waf',
    message: input.message,
    rule: input.rule.id,
    category: input.rule.category,
  }

  if (!wantsHtml) {
    return json(payload, input.status, { 'x-shieldforge-rule': input.rule.id })
  }

  // Friendly HTML page for browsers
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Blocked by ShieldForge</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b1020;color:#e8edf8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#141b31;border:1px solid #263254;border-radius:14px;padding:2rem;max-width:520px;text-align:center}
h1{color:#f87171;margin-top:0}
.badge{display:inline-block;background:#263254;border:1px solid #3a4a78;border-radius:999px;padding:.25rem .75rem;font-size:.85rem;margin:.25rem}
pre{background:#060a14;padding:1rem;border-radius:8px;overflow:auto;text-align:left}
a{color:#60a5fa}
</style></head><body>
<div class="card">
<h1>🛡 Request blocked</h1>
<p>The ShieldForge reverse proxy stopped this request because it matched a security rule.</p>
<div class="badge"><strong>Rule:</strong> ${payload.rule}</div>
<div class="badge"><strong>Category:</strong> ${payload.category}</div>
<div class="badge"><strong>Action:</strong> ${input.blockedBy === 'ml_block' ? 'ML auto-block' : 'Rule block'}</div>
<pre>${JSON.stringify(payload, null, 2)}</pre>
<p><a href="${input.request.headers.get('referer') || '/'}">← Go back</a></p>
</div></body></html>`
  return new Response(html, {
    status: input.status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-shieldforge-rule': input.rule.id,
    },
  })
}

function forwardHeaders(request: Request, target: ProxyTarget): Headers {
  const headers = new Headers()
  request.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (HOP_BY_HOP.has(lower) || lower === 'host' || lower === 'content-length') return
    if (lower.startsWith('x-vercel-')) return
    headers.set(key, value)
  })

  // Ask for an identity body so upstream Content-Encoding cannot disagree
  // with the response we stream back.
  headers.set('accept-encoding', 'identity')
  headers.set('x-shieldforge-origin', target.origin.path_prefix)
  const requestUrl = new URL(request.url)
  headers.set('x-forwarded-proto', requestUrl.protocol.replace(':', ''))
  headers.set('x-forwarded-host', request.headers.get('host') ?? requestUrl.host)
  if (target.publicPrefix) headers.set('x-forwarded-prefix', target.publicPrefix)
  const ip = clientIp(request)
  if (ip !== 'unknown') headers.set('x-forwarded-for', ip)
  return headers
}

export async function handleProxy(request: Request, target: ProxyTarget): Promise<Response> {
  const startedAt = Date.now()
  const url = new URL(request.url)
  const method = request.method.toUpperCase()
  const ip = clientIp(request)
  const userAgent = request.headers.get('user-agent') ?? ''
  const referer = request.headers.get('referer') ?? ''
  const cookieHeader = request.headers.get('cookie') ?? ''
  const { origin, upstreamPath, publicPath, publicPrefix } = target

  if (await isIpBlocked(ip)) {
    return blocked({
      status: 403,
      rule: { id: 'ml-auto-block', category: 'ml_auto_block' },
      blockedBy: 'ml_block',
      message: 'This IP is temporarily blocked by the enforce policy.',
      origin,
      method,
      path: publicPath,
      query: queryOf(url),
      ip,
      userAgent,
      referer,
      cookieHeader,
      startedAt,
      request,
    })
  }

  // Buffer the body once: WAF needs to inspect it, fetch needs to forward it.
  // shortcut: bodies up to memory, stream only if large uploads become real.
  let body: ArrayBuffer | undefined
  let bodyText = ''
  if (method !== 'GET' && method !== 'HEAD') {
    const buffer = await request.arrayBuffer()
    if (buffer.byteLength > 0) {
      body = buffer
      bodyText = new TextDecoder().decode(buffer.slice(0, 1_000_000))
    }
  }

  // Defence in depth: middleware already checked path/query. This also covers
  // bodies, which Edge middleware cannot read.
  const waf = inspectRequest({ path: publicPath, query: url.search, body: bodyText, userAgent })
  if (waf.hit) {
    return blocked({
      status: 403,
      rule: waf.rule,
      blockedBy: 'rule',
      message: `Request blocked by the rule-based WAF (${waf.rule.id}).`,
      origin,
      method,
      path: publicPath,
      query: queryOf(url),
      ip,
      userAgent,
      referer,
      cookieHeader,
      startedAt,
      request,
    })
  }

  const upstreamUrl = buildUpstreamUrl(origin, upstreamPath, url.search)

  let upstream: Response
  try {
    upstream = await fetch(upstreamUrl, {
      method,
      headers: forwardHeaders(request, target),
      body,
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(Number(process.env.PROXY_TIMEOUT_MS ?? 25_000)),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'upstream fetch failed'
    console.error(`[shieldforge] upstream error for ${upstreamUrl.origin}: ${message}`)

    const bodyForEvent: EmitInput = {
      origin,
      method,
      path: publicPath,
      query: queryOf(url),
      ip,
      userAgent,
      referer,
      statusCode: 502,
      durationMs: Date.now() - startedAt,
      ruleHit: null,
      blockedBy: null,
      cookies: null,
      missingSecurityHeaders: [],
      contentLength: 0,
      upstreamError: message,
    }
    after(() => emitAfterResponse(bodyForEvent, cookieHeader))

    return json(
      {
        error: 'bad_gateway',
        message: 'The origin could not be reached.',
        origin: origin.origin_url,
      },
      502,
    )
  }

  const cookies: CookieInspection = inspectCookies(upstream.headers)
  const missing = missingSecurityHeaders(upstream.headers)
  const contentLength = Number(upstream.headers.get('content-length') ?? 0) || 0

  const responseHeaders = new Headers()
  upstream.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (lower === 'set-cookie') return
    if (HOP_BY_HOP.has(lower) || lower === 'content-length' || lower === 'content-encoding') return
    responseHeaders.append(key, value)
  })

  for (const cookie of getSetCookieHeaders(upstream.headers)) {
    // Flags were inspected above; only Domain/Path are rewritten here.
    responseHeaders.append('set-cookie', rewriteSetCookie(cookie, publicPrefix))
  }

  const location = responseHeaders.get('location')
  if (location) {
    responseHeaders.set('location', rewriteLocation(location, origin, upstreamUrl, publicPrefix))
  }

  const eventInput: EmitInput = {
    origin,
    method,
    path: publicPath,
    query: queryOf(url),
    ip,
    userAgent,
    referer,
    statusCode: upstream.status,
    durationMs: Date.now() - startedAt,
    ruleHit: null,
    blockedBy: null,
    cookies,
    missingSecurityHeaders: missing,
    contentLength,
  }

  // Fire-and-forget from the visitor's point of view.
  after(() => emitAfterResponse(eventInput, cookieHeader))

  const noBody =
    method === 'HEAD' || upstream.status === 204 || upstream.status === 304 || !upstream.body

  return new Response(noBody ? null : upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  })
}
