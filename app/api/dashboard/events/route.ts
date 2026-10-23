import { NextRequest, NextResponse } from 'next/server'
import { getOrigins } from '@/lib/origins'
import { recordEvent, listEvents } from '@/lib/event-store'

export async function GET(request: NextRequest): Promise<NextResponse> {
  const { searchParams } = new URL(request.url)
  const limit = Math.min(parseInt(searchParams.get('limit') ?? '100', 10), 500)
  const originId = searchParams.get('origin_id') ?? undefined

  const snapshot = await listEvents(500)
  let events = snapshot.events

  if (originId) {
    events = events.filter((e) => e.origin_id === originId)
  }

  events = events.slice(0, limit)

  const { events: _snapshotEvents, ...restSnapshot } = snapshot
  return NextResponse.json({ events, ...restSnapshot })
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { event, finding, incident } = body as {
      event: any
      finding?: any
      incident?: any
    }

    if (event) recordEvent(event)

    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error('[shieldforge] /api/dashboard/events error', error)
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }
}