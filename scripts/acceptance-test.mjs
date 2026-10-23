#!/usr/bin/env node
/**
 * End-to-end acceptance checks for the ShieldForge proxy.
 *
 * Starts a tiny local origin + the Next dev server, then proves:
 *   1 normal proxy pass-through       5 weak-cookie flag capture (no value leak)
 *   2 XSS query blocked              6 missing security headers recorded
 *   3 SQLi body blocked              7 rate limit after 50+ rapid requests
 *   4 traversal + webshell blocked   8 second origin routing
 *                                    9 ML service dead -> rule WAF still works
 *
 * Run: npm run test:acceptance
 * Keep the server for manual poking: npm run test:acceptance:keep
 */
import { spawn } from 'node:child_process'
import http from 'node:http'
import process from 'node:process'

const PORT = Number(process.env.TEST_PORT ?? 3100)
const ORIGIN_PORT = Number(process.env.TEST_ORIGIN_PORT ?? 4321)
const ORIGIN2_PORT = ORIGIN_PORT + 1
const BASE = `http://127.0.0.1:${PORT}`
const ORIGIN = `http://127.0.0.1:${ORIGIN_PORT}`
const ORIGIN2 = `http://127.0.0.1:${ORIGIN2_PORT}`
const COOKIE_VALUE = 'sfcookie_supersecret_value_do_not_log'

const results = []
let nextProcess = null
let originServer = null
let originServer2 = null
let nextLog = ''

function pass(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `\n      ${detail}` : ''}`)
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function request(path, init = {}) {
  const started = Date.now()
  const response = await fetch(`${BASE}${path}`, {
    redirect: 'manual',
    ...init,
  })
  const text = await response.text()
  return {
    status: response.status,
    text,
    headers: response.headers,
    durationMs: Date.now() - started,
  }
}

async function waitForEvent(predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const response = await request('/api/dashboard/events?limit=100')
    if (response.status === 200) {
      const data = JSON.parse(response.text)
      const found = data.events.find(predicate)
      if (found) return found
    }
    await sleep(400)
  }
  return null
}

function startOrigin() {
  originServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', ORIGIN)

    if (url.pathname === '/cookie') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'set-cookie': `session=${COOKIE_VALUE}; Path=/`,
      })
      res.end('cookie set')
      return
    }

    if (url.pathname === '/echo') {
      let body = ''
      req.on('data', (chunk) => { body += chunk })
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ method: req.method, url: req.url, body }))
      })
      return
    }

    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('local origin ok')
  })

  originServer2 = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', ORIGIN2)

    if (url.pathname === '/cookie') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'set-cookie': `session=${COOKIE_VALUE}; Path=/`,
      })
      res.end('cookie set')
      return
    }

    if (url.pathname === '/echo') {
      let body = ''
      req.on('data', (chunk) => { body += chunk })
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ method: req.method, url: req.url, body }))
      })
      return
    }

    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('local origin 2 ok')
  })

  return Promise.all([
    new Promise((resolve, reject) => {
      originServer.once('error', reject)
      originServer.listen(ORIGIN_PORT, '127.0.0.1', resolve)
    }),
    new Promise((resolve, reject) => {
      originServer2.once('error', reject)
      originServer2.listen(ORIGIN2_PORT, '127.0.0.1', resolve)
    }),
  ])
}

function startProxy() {
  // Second local origin on a different port so the test is fully local.
  const ORIGIN2_PORT = ORIGIN_PORT + 1
  const ORIGIN2 = `http://127.0.0.1:${ORIGIN2_PORT}`
  const origins = [
    {
      path_prefix: '/t/local',
      origin_url: ORIGIN,
      origin_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      name: 'Local acceptance origin',
    },
    {
      path_prefix: '/t/shop',
      origin_url: ORIGIN2,
      origin_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      name: 'Second local origin',
    },
  ]

  const env = {
    ...process.env,
    NEXT_TELEMETRY_DISABLED: '1',
    USE_REAL_ML: 'true',
    // Deliberately unreachable: proves the proxy fails open to rules.
    ML_SERVICE_URL: 'http://127.0.0.1:59999',
    WRITE_TO_SUPABASE: 'false',
    POLICY_MODE: 'shadow',
    RATE_LIMIT_MAX: '50',
    RATE_LIMIT_WINDOW_MS: '20000',
    ALLOW_PRIVATE_ORIGINS: 'true',
    PROXY_SHARED_SECRET: 'acceptance-test-secret',
    ORIGINS_JSON: JSON.stringify(origins),
  }

  nextProcess = spawn('npm', ['run', 'dev', '--', '-p', String(PORT)], {
    cwd: process.cwd(),
    env,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  nextProcess.stdout.on('data', (chunk) => {
    nextLog += chunk.toString()
  })
  nextProcess.stderr.on('data', (chunk) => {
    nextLog += chunk.toString()
  })
}

async function waitForReady(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/dashboard`)
      if (response.ok) return
    } catch {
      // Server is still starting.
    }
    await sleep(1000)
  }
  throw new Error(`Proxy did not become ready within ${timeoutMs}ms.\n${nextLog.slice(-4000)}`)
}

function cleanup() {
  if (nextProcess) {
    try {
      process.kill(-nextProcess.pid, 'SIGTERM')
    } catch {
      nextProcess.kill('SIGTERM')
    }
    nextProcess = null
  }
  if (originServer) {
    originServer.close()
    originServer = null
  }
  if (originServer2) {
    originServer2.close()
    originServer2 = null
  }
}

async function main() {
  console.log(`Starting local origin on ${ORIGIN}`)
  await startOrigin()

  console.log(`Starting proxy on ${BASE} (ML deliberately down at 127.0.0.1:59999)`)
  startProxy()
  await waitForReady()
  console.log('Proxy ready. Running checks...\n')

  // 1. Transparent normal GET
  const direct = await fetch(`${ORIGIN}/`)
  const directText = await direct.text()
  const normal = await request('/t/local')
  pass(
    'Normal GET returns the origin content',
    normal.status === 200 && normal.text === directText,
    `proxy ${normal.status} in ${normal.durationMs}ms; direct origin ${direct.status}`,
  )

  // 2. XSS query
  const xss = await request(`/t/local?q=${encodeURIComponent('<script>alert(1)</script>')}`)
  pass(
    'XSS in query gets 403 from the rule WAF',
    xss.status === 403 && xss.text.includes('"category":"xss"'),
    `${xss.status} ${xss.text.slice(0, 160)}`,
  )

  // 3. SQLi body (plus-encoded form body, like a real form post)
  const sqli = await request('/t/local/echo', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: "username=admin&password=x'+UNION+SELECT+password+FROM+users--",
  })
  pass(
    'UNION SELECT in POST body gets 403',
    sqli.status === 403 && sqli.text.includes('"category":"sqli"'),
    `${sqli.status} ${sqli.text.slice(0, 160)}`,
  )

  // 4. Traversal + webshell
  const traversal = await request(`/t/local?file=${encodeURIComponent('../../etc/passwd')}`)
  pass(
    'Path traversal gets 403',
    traversal.status === 403 && traversal.text.includes('"category":"lfi"'),
    `${traversal.status} ${traversal.text.slice(0, 160)}`,
  )

  const webshell = await request(`/t/local?cmd=${encodeURIComponent("system('id')")}`)
  pass(
    'PHP webshell signature gets 403',
    webshell.status === 403 && webshell.text.includes('"category":"php_rce"'),
    `${webshell.status} ${webshell.text.slice(0, 160)}`,
  )

  // 5. Cookie flags, never the value
  const cookie = await request('/t/local/cookie')
  const cookieEvent = await waitForEvent(
    (event) => event.path === '/t/local/cookie' && event.cookie_count > 0,
  )
  pass(
    'Weak cookie flags are recorded (httponly=false)',
    cookie.status === 200 && cookieEvent?.set_cookie_flags?.httponly === false,
    cookieEvent
      ? `flags=${JSON.stringify(cookieEvent.set_cookie_flags)}`
      : 'no cookie event observed',
  )

  const allEvents = await request('/api/dashboard/events?limit=100')
  pass(
    'Cookie value never appears in stored events',
    !allEvents.text.includes(COOKIE_VALUE),
    allEvents.text.includes(COOKIE_VALUE) ? 'VALUE LEAKED' : 'value absent from event JSON',
  )

  pass(
    'Cookie value never appears in server logs',
    !nextLog.includes(COOKIE_VALUE),
    nextLog.includes(COOKIE_VALUE) ? 'VALUE LEAKED' : 'value absent from dev-server log',
  )

  // 6. Missing headers
  pass(
    'Missing security headers are recorded',
    Array.isArray(cookieEvent?.missing_security_headers) &&
      cookieEvent.missing_security_headers.includes('content-security-policy') &&
      cookieEvent.missing_security_headers.includes('x-content-type-options'),
    cookieEvent?.missing_security_headers?.join(', ') ?? 'no event',
  )

  // 7. Rate limit: 60 rapid HEADs on the same origin prefix
  const burst = await Promise.all(
    Array.from({ length: 60 }, () =>
      fetch(`${BASE}/t/local/__rate_limit_probe__`, { method: 'HEAD' })
        .then((response) => response.status)
        .catch(() => 0),
    ),
  )
  const limited = burst.filter((status) => status === 429).length
  pass(
    '50+ rapid requests trigger the rate limiter',
    limited > 0,
    `${limited}/60 returned 429 (limit 50 / 20s)`,
  )

  // 8. Second origin is independent of the rate-limited first origin
  const second = await request('/t/shop')
  pass(
    'Second registered origin routes independently',
    second.status === 200 && second.text.includes('local origin 2 ok'),
    `${second.status} in ${second.durationMs}ms`,
  )

  // 9. Fail-open: ML is unreachable for every classification in this run
  const normalEvent = await waitForEvent(
    (event) => event.path === '/t/local' && event.status_code === 200 && event.method === 'GET',
  )
  pass(
    'ML service down: proxy still serves and falls back',
    normalEvent?.ml_source === 'mock-fallback',
    normalEvent
      ? `ml_source=${normalEvent.ml_source} error=${normalEvent.ml_error}`
      : 'no normal event observed',
  )

  // 10. Fail-open still blocks rules even with ML down
  pass(
    'ML down: rule-based blocking still works',
    xss.status === 403 && sqli.status === 403,
    'XSS and SQLi checks above were performed with the ML URL unreachable',
  )

  console.log('\n--- summary ---')
  const failed = results.filter((result) => !result.ok)
  for (const result of results) console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}`)
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`)

  if (failed.length > 0) {
    console.error('\nRecent dev-server log:\n' + nextLog.slice(-5000))
    process.exitCode = 1
  }
}

process.on('SIGINT', () => {
  cleanup()
  process.exit(130)
})
process.on('SIGTERM', () => {
  cleanup()
  process.exit(143)
})
process.on('exit', cleanup)

main()
  .catch((error) => {
    console.error(error)
    console.error('\nRecent dev-server log:\n' + nextLog.slice(-5000))
    process.exitCode = 1
  })
  .finally(() => {
    if (process.env.KEEP_SERVER !== '1') cleanup()
  })
