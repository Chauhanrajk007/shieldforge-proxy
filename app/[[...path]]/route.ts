import { matchOrigin } from '@/lib/origins'
import { handleProxy } from '@/lib/proxy-handler'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const maxDuration = 30

function notFound(pathname: string): Response {
  return Response.json(
    {
      error: 'origin_not_registered',
      message: 'No origin is registered for this path prefix.',
      hint: 'Add one in the dashboard, config/origins.json, or ORIGINS_JSON.',
      path: pathname,
    },
    { status: 404, headers: { 'cache-control': 'no-store' } },
  )
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url)
  const matched = matchOrigin(url.pathname)
  if (!matched) return notFound(url.pathname)

  return handleProxy(request, {
    origin: matched.origin,
    upstreamPath: matched.upstreamPath,
    publicPath: url.pathname,
    publicPrefix: matched.origin.path_prefix,
    hostMode: false,
  })
}

export const GET = handle
export const POST = handle
export const PUT = handle
export const PATCH = handle
export const DELETE = handle
export const HEAD = handle
export const OPTIONS = handle
