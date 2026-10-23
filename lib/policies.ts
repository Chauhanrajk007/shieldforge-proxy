import type { OriginConfig, Policy, PolicyMode } from './types'

const DEFAULT_POLICY: Policy = {
  auto_block_threshold: 0.9,
  alert_threshold: 0.6,
  mode: 'shadow',
}

function numberFromEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.min(1, Math.max(0, parsed)) : fallback
}

function modeFromEnv(value: string | undefined, fallback: PolicyMode): PolicyMode {
  return value === 'enforce' || value === 'shadow' ? value : fallback
}

/**
 * Boundary 4: the dashboard owns policies in Supabase. Round 1 keeps a local
 * default and lets each origin override it in config/origins.json. Env vars
 * are the quick demo switch (POLICY_MODE=enforce).
 */
export function getPolicy(origin?: OriginConfig | null): Policy {
  const base: Policy = {
    ...DEFAULT_POLICY,
    ...(origin?.policy ?? {}),
    auto_block_threshold: numberFromEnv(
      process.env.AUTO_BLOCK_THRESHOLD,
      origin?.policy?.auto_block_threshold ?? DEFAULT_POLICY.auto_block_threshold,
    ),
    alert_threshold: numberFromEnv(
      process.env.ALERT_THRESHOLD,
      origin?.policy?.alert_threshold ?? DEFAULT_POLICY.alert_threshold,
    ),
    mode: modeFromEnv(process.env.POLICY_MODE, origin?.policy?.mode ?? DEFAULT_POLICY.mode),
  }

  // A useful warning rather than a silent misconfiguration.
  if (base.alert_threshold > base.auto_block_threshold) {
    base.alert_threshold = base.auto_block_threshold
  }

  return base
}

export function mlReachesBlockThreshold(confidence: number, policy: Policy): boolean {
  return confidence >= policy.auto_block_threshold
}

export function mlReachesAlertThreshold(confidence: number, policy: Policy): boolean {
  return confidence >= policy.alert_threshold
}
