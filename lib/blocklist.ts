import { getServerSupabase } from './supabase/server'

type BlockEntry = { ip: string; expires_at: number; created_at: number }

const MEMORY_FALLBACK = new Map<string, number>()

function getMemoryStore(): Map<string, number> {
  const globalWithStore = globalThis as typeof globalThis & { __shieldBlocklistMemory?: Map<string, number> }
  if (!globalWithStore.__shieldBlocklistMemory) {
    globalWithStore.__shieldBlocklistMemory = new Map()
  }
  return globalWithStore.__shieldBlocklistMemory
}

async function getSupabaseClient() {
  const supabase = getServerSupabase()
  if (!supabase) return null
  return supabase
}

/**
 * Persistent IP blocklist backed by Supabase with in-memory fallback.
 * Table: ip_blocks (ip, expires_at, created_at)
 * Index on (ip) for fast lookups.
 */
export async function blockIp(ip: string, durationMs = 10 * 60_000): Promise<void> {
  if (!ip || ip === 'unknown') return
  const expiresAt = Date.now() + durationMs

  // Always update memory for fast path
  getMemoryStore().set(ip, expiresAt)

  const supabase = await getSupabaseClient()
  if (!supabase) return

  try {
    await supabase.from('ip_blocks').upsert({
      ip,
      expires_at: new Date(expiresAt).toISOString(),
      created_at: new Date().toISOString(),
    }, { onConflict: 'ip' })
  } catch (error) {
    console.warn('[shieldforge] Failed to persist IP block to Supabase:', error)
  }
}

export async function isIpBlocked(ip: string): Promise<boolean> {
  if (!ip) return false

  // Fast path: check memory first
  const memoryStore = getMemoryStore()
  const memExpiresAt = memoryStore.get(ip)
  if (memExpiresAt !== undefined) {
    if (memExpiresAt <= Date.now()) {
      memoryStore.delete(ip)
      return false
    }
    return true
  }

  // Check Supabase
  const supabase = await getSupabaseClient()
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('ip_blocks')
        .select('expires_at')
        .eq('ip', ip)
        .maybeSingle()

      if (!error && data) {
        const expiresAt = new Date(data.expires_at).getTime()
        if (expiresAt > Date.now()) {
          memoryStore.set(ip, expiresAt)
          return true
        } else {
          // Expired - clean up
          await supabase.from('ip_blocks').delete().eq('ip', ip)
          return false
        }
      }
    } catch (error) {
      console.warn('[shieldforge] Failed to check IP block in Supabase:', error)
    }
  }

  return false
}

export async function listBlockedIps(): Promise<Array<{ ip: string; expiresAt: number }>> {
  const result: Array<{ ip: string; expiresAt: number }> = []
  const now = Date.now()

  // Add memory entries
  for (const [ip, expiresAt] of getMemoryStore()) {
    if (expiresAt > now) result.push({ ip, expiresAt })
  }

  const supabase = await getSupabaseClient()
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('ip_blocks')
        .select('ip, expires_at')
        .gt('expires_at', new Date().toISOString())

      if (!error && data) {
        for (const row of data) {
          const expiresAt = new Date(row.expires_at).getTime()
          if (expiresAt > now) {
            result.push({ ip: row.ip, expiresAt })
            getMemoryStore().set(row.ip, expiresAt)
          }
        }
      }
    } catch (error) {
      console.warn('[shieldforge] Failed to list blocked IPs from Supabase:', error)
    }
  }

  // Deduplicate
  const seen = new Set<string>()
  return result.filter(({ ip }) => {
    if (seen.has(ip)) return false
    seen.add(ip)
    return true
  })
}

/**
 * Clean up expired entries from Supabase (run periodically)
 */
export async function cleanupExpiredBlocks(): Promise<number> {
  const supabase = await getSupabaseClient()
  if (!supabase) return 0

  try {
    const { data, error } = await supabase
      .from('ip_blocks')
      .delete()
      .lt('expires_at', new Date().toISOString())
      .select('ip')

    if (error) throw error
    return data?.length ?? 0
  } catch (error) {
    console.warn('[shieldforge] Failed to cleanup expired IP blocks:', error)
    return 0
  }
}