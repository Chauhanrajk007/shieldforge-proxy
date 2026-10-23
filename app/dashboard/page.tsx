import Dashboard from './Dashboard'
import { getOrigins } from '@/lib/origins'
import { getPolicy } from '@/lib/policies'
import { rateLimitConfig } from '@/lib/rate-limit'

export const dynamic = 'force-dynamic'

export default function DashboardPage() {
  const origins = getOrigins().map((origin) => ({
    ...origin,
    policy: getPolicy(origin),
  }))

  const flags = {
    useRealMl: process.env.USE_REAL_ML === 'true',
    mlUrl: process.env.ML_SERVICE_URL ?? null,
    writeToSupabase: process.env.WRITE_TO_SUPABASE === 'true',
    supabaseConfigured: Boolean(
      process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY,
    ),
    internalSecretSet: Boolean(process.env.PROXY_SHARED_SECRET),
    configSource: process.env.ORIGINS_JSON ? ('env' as const) : ('file' as const),
  }

  return (
    <Dashboard
      origins={origins}
      flags={flags}
      limits={rateLimitConfig()}
      defaultPolicy={getPolicy()}
    />
  )
}
