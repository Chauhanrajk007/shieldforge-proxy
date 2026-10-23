import { createClient } from '@supabase/supabase-js'

function supabaseConfig(): { url: string; key: string } | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) return null
  return { url: url.replace(/\/$/, ''), key }
}

export function getServerSupabase() {
  const config = supabaseConfig()
  if (!config) return null
  return createClient(config.url, config.key, {
    auth: { persistSession: false },
    db: { schema: 'public' },
  })
}