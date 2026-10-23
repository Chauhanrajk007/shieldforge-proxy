import { NextRequest, NextResponse } from 'next/server'
import { getOrigins, addRuntimeOrigin, removeRuntimeOrigin } from '@/lib/origins'

const INTERNAL_SECRET = process.env.PROXY_SHARED_SECRET

function checkAuth(request: NextRequest): boolean {
  if (!INTERNAL_SECRET) return true
  return request.headers.get('x-shieldforge-internal') === INTERNAL_SECRET
}

export async function GET(): Promise<NextResponse> {
  return NextResponse.json({ origins: getOrigins() })
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!checkAuth(request)) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  try {
    const body = await request.json()
    const result = addRuntimeOrigin(body)
    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: 400 })
    }
    return NextResponse.json({ origin: result.origin })
  } catch (error) {
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  if (!checkAuth(request)) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  const { searchParams } = new URL(request.url)
  const key = searchParams.get('key')
  if (!key) {
    return NextResponse.json({ error: 'missing key' }, { status: 400 })
  }

  const ok = removeRuntimeOrigin(key)
  return NextResponse.json({ ok })
}