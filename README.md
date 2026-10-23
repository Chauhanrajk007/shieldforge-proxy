# ShieldForge — Part 1: Reverse Proxy & Edge Enforcement

This is the **data plane** for ShieldForge. It sits in front of any origin (a public URL or
Part 4's deliberately-vulnerable `victim-shop.vercel.app`) and serves it under a path prefix:

```
https://shield-proxy.vercel.app/t/victim-shop  →  https://victim-shop.vercel.app
```

While proxying it does two jobs at different speeds:

| Job | When | Can it block? | Depends on ML/DB? |
|---|---|---|---|
| Rate limit + rule WAF | synchronously, before the origin fetch | **yes** (403 / 429) | **no** |
| ML classification + event/finding/incident write | after the visitor already has the response | only the *next* request in `enforce` mode | yes, and it fails open |

That split is the whole design. The synchronous layer is the fail-open safety net; the
asynchronous layer is the intelligence. Read the walkthrough below and the demo becomes easy
to explain to judges.

> **Stated tradeoff:** Vercel serverless has cold starts and execution-time limits, and this
> demo buffers request bodies for WAF inspection. It is a hackathon data plane, not a 24/7
> production WAF. Production would move this to a dedicated proxy process (or
> Cloudflare/nginx) with streaming bodies, a distributed rate limiter and durable event
> storage.

---

## 1. Quick start

```bash
cd proxy
npm install
cp .env.example .env.local     # defaults are demo-friendly: mock ML, console DB
npm run dev
```

Then open:

```
http://localhost:3000/dashboard
```

`/` redirects to `/dashboard`; the dashboard is the control room, not proxied traffic.

Run the full acceptance suite (it starts its own local origin and a proxy on port 3100):

```bash
npm run test:acceptance
```

Keep the test server alive for manual poking:

```bash
npm run test:acceptance:keep
# then use http://localhost:3100/dashboard
```

---

## 2. The request lifecycle (the part to understand)

```
visitor
  │
  ▼
middleware.ts                         SYNCHRONOUS · Edge runtime
  ├─ rate limit (per IP + origin prefix) ─────────────► 429 + async event
  ├─ rule WAF on path / query / User-Agent ───────────► 403 + async event
  └─ pass
       │
       ▼
app/[[...path]]/route.ts               SYNCHRONOUS · Node runtime
  ├─ find origin by longest path prefix
  ├─ read body once, run the same rule WAF on the body ► 403 + async event
  ├─ fetch(origin, TLS verified, redirect: manual)
  ├─ inspect response headers:
  │    • Set-Cookie flags ONLY (httponly / secure / samesite)
  │    • which security headers are missing
  ├─ rewrite Location + Set-Cookie Domain/Path for the proxy host
  ├─ return the upstream body as a stream  ◄──────────── visitor has the response now
  │
  └─ after(): emitEvent()                ASYNCHRONOUS
       ├─ POST {ML_SERVICE_URL}/classify   (or local keyword mock)
       ├─ build Boundary 1 payload
       ├─ write Boundary 2 event
       ├─ maybe write finding + incident
       └─ console.log when WRITE_TO_SUPABASE=false
```

Why two WAF layers?

- Next.js **Edge middleware cannot read request bodies**. So middleware catches path/query
  attacks before the origin fetch, and the Node route repeats the check with the body. It is
  defence in depth, not duplicated effort: the first layer saves a round trip, the second
  layer is the only one that can see `UNION SELECT` in a POST body.
- The visitor **never waits** for `/classify` or Supabase. The route registers the async work
  with `after()` and returns the upstream `ReadableStream` immediately.
- The ML result cannot block the request that produced it — that response is already gone.
  In `enforce` mode a high-confidence detection temp-blocks that IP, so the **next** request
  is rejected by middleware. Rule-based blocks are always immediate.

---

## 3. Files

```
proxy/
├── middleware.ts                    sync rate limit + path/query WAF + root redirect
├── app/
│   ├── [[...path]]/route.ts         proxy handler, body WAF, response inspection
│   ├── dashboard/page.tsx           server entry for the control room
│   ├── dashboard/Dashboard.tsx      client UI: test lab, live events, origins, policy
│   └── api/
│       ├── internal/events/route.ts  sink for middleware-blocked events
│       └── dashboard/events/route.ts in-memory event feed for the dashboard
├── lib/
│   ├── origins.ts                   registry + Boundary 4 shape compatibility
│   ├── policies.ts                  shadow/enforce + thresholds (Boundary 4 mock)
│   ├── waf.ts                       rule signatures, decode-twice, body-aware
│   ├── rate-limit.ts                in-memory fixed-window limiter
│   ├── blocklist.ts                 enforce-mode temp blocks
│   ├── ml.ts                        mock classifier + real /classify call
│   ├── emit.ts                      Boundary 1 + Boundary 2 orchestration
│   ├── supabase.ts                  REST inserts when WRITE_TO_SUPABASE=true
│   ├── cookies.ts                   flags-only parsing + Domain/Path rewrite
│   ├── security-headers.ts          missing-header check
│   ├── event-store.ts               demo dashboard feed (in-memory)
│   ├── redact.ts                    removes sensitive query values from events
│   ├── hash.ts                      SHA-256 prefix for session_token_hash
│   └── ip.ts                        trusted-proxy-aware client IP
├── config/origins.json              the demo origin registry
├── scripts/acceptance-test.mjs      end-to-end checks with a local origin
└── .env.example
```

---

## 4. Origin registration

For the hackathon the registry is JSON or an env var. `config/origins.json` ships with three
safe public origins:

| Prefix | Origin | Use |
|---|---|---|
| `/t/shop` | `https://example.com` | normal traffic / WAF tests |
| `/t/echo` | `https://httpbin.org` | echo + deliberately weak cookie |
| `/t/fast` | `https://httpbingo.org` | proves a second origin works |

Add an origin by editing the file:

```json
{
  "path_prefix": "/t/victim-shop",
  "origin_url": "https://victim-shop.vercel.app",
  "origin_id": "the-uuid-from-supabase-origins-table",
  "name": "Victim Shop"
}
```

Or without a redeploy:

```bash
ORIGINS_JSON='[{"path_prefix":"/t/victim-shop","origin_url":"https://victim-shop.vercel.app"}]' npm run dev
```

`ORIGINS_JSON` replaces the file entirely. The loader also accepts Part 3's Boundary 4 shape
(`proxy_path` instead of `path_prefix`), so when the dashboard starts writing `origins` rows
the same code can read them.

**Routing rules:** longest prefix wins, the prefix is stripped before forwarding, the original
query string is preserved. `Location` headers pointing back at the origin are rewritten to the
proxy prefix. `Set-Cookie` loses `Domain` and its `Path` is scoped under the prefix, so the
cookie actually lands on the proxy host.

**SSRF guard:** origins must be `https://` and public by default. Local `http://` origins are
rejected unless `ALLOW_PRIVATE_ORIGINS=true` (the acceptance script sets it for its local
origin). `169.254.169.254`, private ranges, credentials in the URL and query/hash in the origin
URL are rejected.

---

## 5. Rule-based WAF

Rules live in `lib/waf.ts`. They run on the path, query, User-Agent and (in the route) body.
Each value is checked raw, plus-unescaped, and URL-decoded up to two rounds, so
`%3Cscript%3E`, `%252e%252e%252f` and `UNION+SELECT` are caught.

| Rule id | Category | Catches |
|---|---|---|
| `xss-script-tag` | xss | `<script>` |
| `xss-javascript-uri` / `xss-event-handler` | xss | `javascript:`, `onerror=`, `onload=` |
| `xss-svg-payload` | xss | SVG onload payloads |
| `sqli-union-select` | sqli | `UNION ... SELECT` |
| `sqli-tautology` | sqli | `' OR 1=1` |
| `sqli-time-based` | sqli | `sleep(`, `benchmark(` |
| `sqli-stacked` | sqli | `; DROP ...` |
| `sqli-schema-probe` | sqli | `information_schema` |
| `path-traversal` | lfi | `../`, `%2e%2e%2f`, `/etc/passwd` |
| `php-shell-function` | php_rce | `eval(`, `system(`, `base64_decode(` |
| `php-open-tag` / `php-stream-wrapper` | php_rce | `<?php`, `php://filter` |
| `webshell-filename` | php_rce | `c99.php`, `r57.php`, `wso.php` |
| `scanner-signature` | scanner | `sqlmap`, `nikto`, `nuclei`, ... |

This is intentionally a **small signature WAF**, not a replacement for a real one. It is the
part that keeps working when the ML service is dead. A false positive is visible in the event
stream (`rule_hit`) and returns a JSON 403 with the rule id.

---

## 6. Rate limiting

- Fixed window, per **IP + origin prefix**.
- Defaults: **50 requests / 20 seconds** (`RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_MS`).
- The 51st request in the window gets `429` with `Retry-After`.
- Separate origins do not share a bucket, so a burst on `/t/shop` does not block `/t/fast`.

The store is an in-memory `Map`. **On Vercel this is per serverless instance**, so it is an
approximation, not a global limiter. The production upgrade is Upstash Redis (a single
`INCR` + `EXPIRE`, or a sliding-window script); the call site in `middleware.ts` would not
change shape. The event feed and enforce blocklist have the same per-instance caveat.

---

## 7. What the response inspector records

For every proxied response:

1. **Cookie flags only** — `httponly`, `secure`, `samesite`, plus a count. The cookie name and
   value never enter the event, the logs, or Supabase. If HttpOnly is missing, the server log
   prints a flags-only warning and the event includes a `weak_cookie` finding.
2. **Missing security headers** — `Content-Security-Policy`, `X-Content-Type-Options`,
   `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`.
3. **Status, content length, duration** and the request features sent to ML.

Sensitive query parameters (`token`, `password`, `session`, `auth`, `api_key`, `jwt`, ...) are
replaced with `[redacted]` before an event is stored. The session token hash is a 16-character
SHA-256 prefix — never the raw cookie.

---

## 8. Async detection pipeline

### Boundary 1 — Proxy → ML

`emitEvent()` builds exactly this and calls `POST {ML_SERVICE_URL}/classify`:

```json
{
  "request": {
    "method": "GET",
    "path": "/t/shop",
    "query": "q=%3Cscript%3E...",
    "headers": { "user-agent": "...", "referer": "" },
    "ip": "203.0.113.4"
  },
  "response_meta": {
    "status_code": 200,
    "set_cookie_flags": { "httponly": false, "secure": true, "samesite": "lax" },
    "content_length": 1821
  },
  "session_features": {
    "session_token_hash": "sha256-prefix-only",
    "ip_change_count_5min": 0,
    "ua_change_count_5min": 0,
    "asn_changed": false
  }
}
```

`USE_REAL_ML=false` (default): a local keyword classifier returns the same typed response
without any network call. `USE_REAL_ML=true`: the real service is called with a **1.5s
timeout**. Any error, timeout, non-200 or invalid JSON falls back to the mock and records
`ml_source: "mock-fallback"` plus `ml_error` on the event. That is the fail-open design.

### Boundary 2 — Proxy → Supabase

Each request becomes one `events` row. A `findings` row is created when:

- a rule hit happened, **or**
- ML attacked with `confidence >= policy.alert_threshold` (0.6), **or**
- the response set a cookie without HttpOnly (`weak_cookie`).

An `incidents` row is created when:

- a rule hit happened (action `temp_block` / `rate_limit`), **or**
- ML confidence crosses `auto_block_threshold` (0.9).

In `WRITE_TO_SUPABASE=false` mode the exact payload is pretty-printed to the terminal as
`[shieldforge] mock DB write ...`. The built-in dashboard reads an in-memory feed instead.

---

## 9. Policies: shadow vs enforce (Boundary 4)

The default is:

```json
{ "auto_block_threshold": 0.9, "alert_threshold": 0.6, "mode": "shadow" }
```

Override per origin in `config/origins.json`:

```json
{
  "path_prefix": "/t/shop",
  "origin_url": "https://example.com",
  "policy": { "mode": "enforce", "auto_block_threshold": 0.85 }
}
```

or globally with `POLICY_MODE=enforce`, `AUTO_BLOCK_THRESHOLD=...`,
`ALERT_THRESHOLD=...`.

| Mode | Rule WAF | High-confidence ML |
|---|---|---|
| `shadow` | blocks (403) | logs a finding + incident action `alert`; nothing is blocked |
| `enforce` | blocks (403) | logs, and temp-blocks the IP for 10 min; the **next** request gets 403 |

Part 3 will eventually store policies in Supabase and `PATCH /api/policies/{origin_id}`. The
current `lib/policies.ts` is the deliberate mock; the dashboard shows the active values.

---

## 10. The dashboard

`/dashboard` is a local/dev control room, not a production SOC:

- **Header pills** — real vs mock ML, real vs mock DB, policy mode, rate limit, config source.
- **Stat cards** — requests, blocked, rate-limited, ML-flagged, findings, buffered events.
- **Test Lab** — one click per acceptance test. The result row shows PASS/FAIL, status,
  latency and a short detail. The same requests appear in the event stream.
- **Live event stream** — polls the in-memory feed every 2s. Click a row to see the rule,
  ML class/confidence/risk, cookie flags, missing headers, finding/incident and the raw
  redacted JSON.
- **Custom request** — choose an origin, method, path/query and body; it goes through the real
  proxy pipeline, including the WAF.
- **Registered origins / Policy / Why this design** — the config the proxy is actually using.

The Test Lab presets map directly to the acceptance checklist:

| Preset | What it proves |
|---|---|
| Normal GET | transparent pass-through |
| XSS in query | synchronous WAF, no ML needed |
| SQLi in body | body inspection in the Node route |
| Path traversal | encoded `../` handling |
| PHP webshell | command/webshell signatures |
| Rate limit burst | 50+ rapid requests get 429 |
| Second origin | prefix routing is not hardcoded to one site |
| Weak Set-Cookie | flags-only inspection + async event |

> The in-memory feed is shared inside one dev/server process. On Vercel each serverless
> instance has its own memory, so use `WRITE_TO_SUPABASE=true` and Part 3's dashboard for the
> multi-instance demo. The local dashboard is for development and for showing the pipeline.

---

## 11. Acceptance tests

### Automated

```bash
cd proxy
npm run test:acceptance
```

It creates a local origin on `:4321`, starts the proxy on `:3100` with
`USE_REAL_ML=true ML_SERVICE_URL=http://127.0.0.1:59999` (deliberately dead), and checks:

```
PASS  Normal GET returns the origin content
PASS  XSS in query gets 403 from the rule WAF
PASS  UNION SELECT in POST body gets 403
PASS  Path traversal gets 403
PASS  PHP webshell signature gets 403
PASS  Weak cookie flags are recorded (httponly=false)
PASS  Cookie value never appears in stored events
PASS  Cookie value never appears in server logs
PASS  Missing security headers are recorded
PASS  50+ rapid requests trigger the rate limiter
PASS  Second registered origin routes independently
PASS  ML service down: proxy still serves and falls back
PASS  ML down: rule-based blocking still works
13/13 checks passed
```

The ML-unreachable half proves the fail-open claim in one run: all rule checks pass while
every `/classify` call is failing.

### Manual curl

```bash
# 1. normal pass-through (compare with https://example.com)
curl -i http://localhost:3000/t/shop

# 2. XSS in query -> 403 xss
curl -i 'http://localhost:3000/t/shop?q=%3Cscript%3Ealert(1)%3C/script%3E'

# 3. SQLi in body -> 403 sqli
curl -i -X POST \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data "username=admin&password=x' UNION SELECT password FROM users--" \
  http://localhost:3000/t/shop/echo

# 4. rate limit -> some 429s
for i in $(seq 1 60); do
  curl -s -o /dev/null -w '%{http_code}\n' -I http://localhost:3000/t/shop/__probe__
done | sort | uniq -c

# 5. weak cookie -> 200, then look at the terminal / event stream (flags only)
curl -i 'http://localhost:3000/t/echo/response-headers?Set-Cookie=session%3Ddemo%3B%20Path%3D%2F'

# 6. second origin -> 200
curl -i http://localhost:3000/t/fast/get

# 7. unknown prefix -> 404 with a hint
curl -i http://localhost:3000/t/not-registered
```

For test 5, the terminal prints a flags-only warning such as:

```
[shieldforge] weak cookie on /t/echo/response-headers: HttpOnly is missing, Secure is missing, SameSite is missing
[shieldforge] 200 GET /t/echo/response-headers rule=- ml=benign:0.05 cookies=1 httponly=false secure=false samesite=none missing_headers=6
```

No cookie value is ever printed. If you want to prove fail-open manually, restart with:

```bash
USE_REAL_ML=true ML_SERVICE_URL=http://127.0.0.1:59999 npm run dev
```

Then repeat tests 2 and 3: they still return 403, and normal events show
`ml_source=mock-fallback`.

---

## 12. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `USE_REAL_ML` | `false` | `true` calls Part 2; `false` uses the local keyword mock |
| `ML_SERVICE_URL` | — | Base URL of Part 2 (the proxy appends `/classify`) |
| `WRITE_TO_SUPABASE` | `false` | `true` writes events/findings/incidents via REST; `false` logs them |
| `NEXT_PUBLIC_SUPABASE_URL` | — | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | — | Server-only key; never expose to the browser |
| `POLICY_MODE` | `shadow` | `shadow` or `enforce` |
| `AUTO_BLOCK_THRESHOLD` | `0.9` | ML confidence that creates an incident / enforce block |
| `ALERT_THRESHOLD` | `0.6` | ML confidence that creates a finding |
| `RATE_LIMIT_MAX` | `50` | Requests per window per IP+prefix |
| `RATE_LIMIT_WINDOW_MS` | `20000` | Window length |
| `ORIGINS_JSON` | — | JSON array; replaces `config/origins.json` |
| `ALLOW_PRIVATE_ORIGINS` | `false` | Allow `http://` and private/localhost origins |
| `PROXY_SHARED_SECRET` | — | Required header on the internal blocked-event sink |
| `PROXY_TIMEOUT_MS` | `25000` | Upstream fetch timeout |

Copy `.env.example` to `.env.local` for local development. Do not commit `.env.local`.

---

## 13. Integration handoff

This module is built to run with **zero other modules deployed**; these are the swaps for the
final integration.

| Boundary | Current mock | Integration step |
|---|---|---|
| **1** Proxy → ML | `lib/ml.ts` keyword mock | `USE_REAL_ML=true`, set `ML_SERVICE_URL` from Part 2 |
| **2** Proxy → Supabase | console log | `WRITE_TO_SUPABASE=true`, set URL + service-role key; replace placeholder `origin_id`s with real `origins.id` rows |
| **4** Policies | `lib/policies.ts` + JSON/env | Part 3 owns the `policies` table and `PATCH /api/policies/[origin_id]`; swap `getPolicy()` to read it |
| **6** Proxy → origin | `/t/shop`, `/t/echo`, `/t/fast` | Add `{ "path_prefix": "/t/victim-shop", "origin_url": "https://victim-shop.vercel.app" }` |

Integration checklist:

- [ ] Part 2 URL shared → `USE_REAL_ML=true`, test `/classify` through the proxy.
- [ ] Part 3 shares Supabase keys and runs `schema.sql` → `WRITE_TO_SUPABASE=true`.
- [ ] The origin UUID in `config/origins.json` exists in Supabase `origins` (event FK).
- [ ] Part 4 deploys the victim app → register it under a new prefix.
- [ ] Confirm `WRITE_TO_SUPABASE=false` still works as the offline demo path.
- [ ] Kill the ML service mid-demo → rules still return 403 (repeat the manual test).
- [ ] Switch `POLICY_MODE=enforce` → a high-confidence ML hit blocks the next request from
      that IP.

**Known integration gap:** the proxy does not yet poll Supabase for origin/policy changes.
Until that swap, adding an origin means editing `ORIGINS_JSON` or `config/origins.json` and
redeploying. That is intentional for Part 1's "zero dependency" requirement; Part 3's
dashboard is the source of truth in the real integration.

---

## 14. Deploying to Vercel

1. Import the repo, set **Root Directory** to `proxy`.
2. Add the env vars from the table above (at minimum `ORIGINS_JSON` if you want to add
   origins without a redeploy).
3. Deploy. `middleware.ts` runs on the Edge runtime; the proxy route is Node runtime
   (`export const runtime = 'nodejs'`) because it needs request bodies and streaming.
4. Set `maxDuration = 30` is already in the route; keep the plan's function limit >= 30s for
   slow origins.
5. If Vercel Deployment Protection is enabled, the middleware's internal POST to
   `/api/internal/events` can be challenged. For the demo, use a public deployment or add a
   protection-bypass header; otherwise blocked-event analytics will be missing (blocking itself
   still works).

Recommended Vercel settings for the demo:

```
USE_REAL_ML=false
WRITE_TO_SUPABASE=false
POLICY_MODE=shadow
ORIGINS_JSON=[{"path_prefix":"/t/shop","origin_url":"https://example.com","origin_id":"..."}]
```

Turn on the real ML/Supabase only after the other parts are deployed and their URLs are
shared.

---

## 15. Known limits / honest tradeoffs

| Limit | Why it matters | Upgrade |
|---|---|---|
| In-memory rate limit | per instance on Vercel; not a global limit | Upstash Redis / sliding window |
| In-memory event feed | dashboard may not see events from another instance | Supabase `events` + Part 3 Realtime |
| In-memory blocklist | enforce mode is per instance | Redis with TTL |
| Body is buffered | large uploads cost memory/time | stream with a capped tee, or enforce at the edge |
| ML is async | cannot block the triggering request | block on the next request (current enforce behavior) |
| Only `Location` + Set-Cookie rewritten | absolute HTML links/assets still point at the origin | HTML rewriting or origin-side relative URLs |
| No auth on `/dashboard` or the internal sink | demo only | auth + `PROXY_SHARED_SECRET` |
| Signature WAF | shallow by design; not a production WAF | ML + managed WAF / OWASP CRS |
| `x-forwarded-for` trust | spoofable if not behind a trusted proxy | platform header (`x-vercel-forwarded-for`) / trusted-proxy config |
| Vercel cold starts | first request can be slow | dedicated proxy process |
| `httpbin.org` is slow/flaky | cookie preset can take seconds | use the local origin in `npm run test:acceptance` |

---

## 16. Troubleshooting

- **404 `origin_not_registered`** — no prefix matches. Check `config/origins.json` /
  `ORIGINS_JSON` and use the exact prefix (longest wins).
- **429 during the demo** — you hit the rate limit burst preset. Wait for the 20s window or
  restart the dev server; other prefixes are unaffected.
- **403 on a normal request** — look at `rule_hit` in the event stream. A query string with
  `<script>` or `../` is supposed to be blocked. Check `lib/waf.ts` if a legitimate value
  matches.
- **No event after a request** — async writes run in `after()`. Wait ~1s or click
  “Refresh stream”. In production check `WRITE_TO_SUPABASE`/Supabase logs.
- **Cookie event missing** — the `httpbin.org` origin is slow; the preset waits up to 10s.
  Use the local acceptance origin for a deterministic check.
- **Supabase insert fails** — check the service-role key, that `schema.sql` ran, and that
  `origin_id` exists in `origins` (foreign key). The visitor response is unaffected; the error
  is logged server-side.
- **ML always `mock-fallback`** — `ML_SERVICE_URL` is unset/unreachable or
  `USE_REAL_ML=false`. This is the intended fail-open path, not a crash.
- **Config changes not picked up** — `next.config.ts` changes restart dev automatically;
  `.env.local` needs a restart.

---

## 17. Why this is a good demo

- The audience sees a **real attack get a 403 instantly**, with no ML or DB in the path.
- The same request creates a **finding** with a confidence score and an AI-ready payload
  moments later, without slowing the response.
- Killing the ML service changes nothing for the visitor — the safety net is independent.
- The dashboard makes the invisible parts visible: rule id, ML class, cookie flags, missing
  headers, create/alert/block decisions.
- Every claim is testable with one command (`npm run test:acceptance`) and each acceptance
  criterion maps to a button in the Test Lab.
