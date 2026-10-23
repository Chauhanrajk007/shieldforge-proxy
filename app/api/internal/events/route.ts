import { NextRequest, NextResponse } from 'next/server'
import { emitEvent } from '@/lib/emit'
import type { EmitInput, WafHit } from '@/lib/types'
import { hashSecret } from '@/lib/hash'

const INTERNAL_SECRET = process.env.PROXY_SHARED_SECRET

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (INTERNAL_SECRET) {
    const provided = request.headers.get('x-shieldforge-internal')
    if (provided !== INTERNAL_SECRET) {
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
    }
  }

  try {
    const body = await request.json()
    const {
      method,
      path,
      query,
      host,
      ip,
      userAgent,
      referer,
      cookieHash,
      statusCode,
      rule,
      blockedBy,
      durationMs,
    } = body as {
      method: string
      path: string
      query: string
      host: string
      ip: string
      userAgent: string
      referer: string
      cookieHash: string
      statusCode: number
      rule: WafHit
      blockedBy: 'rule' | 'rate_limit' | 'ml_block'
      durationMs: number
    }

    const input: EmitInput = {
      origin: null,
      method,
      path,
      query,
      ip,
      userAgent,
      referer,
      cookieHash,
      statusCode,
      durationMs,
      ruleHit: rule,
      blockedBy,
      cookies: null,
      missingSecurityHeaders: [],
      contentLength: 0,
    }

    await emitEvent(input)

    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error('[shieldforge] /api/internal/events error', error)
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }
}