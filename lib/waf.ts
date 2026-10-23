import type { WafHit, WafResult, WafRule } from './types'

/**
 * Synchronous, dependency-free attack signatures. This is the fail-open safety
 * net: it runs before the origin fetch and never calls the ML service or DB.
 */
export const WAF_RULES: WafRule[] = [
  { id: 'xss-script-tag', category: 'xss', pattern: /<script\b/i },
  { id: 'xss-javascript-uri', category: 'xss', pattern: /javascript\s*:/i },
  {
    id: 'xss-event-handler',
    category: 'xss',
    // Match every inline handler, not just the classic five. HTML-entity
    // obfuscation (ontoggle&#61;) still slips past this on purpose; the victim
    // app decodes entities, which is the documented response-side gap.
    pattern: /\bon[a-z]{3,}\s*=/i,
  },
  { id: 'xss-svg-payload', category: 'xss', pattern: /<svg[\s>].*on\w+\s*=/i },
  { id: 'sqli-union-select', category: 'sqli', pattern: /\bunion\b[\s\S]{0,40}\bselect\b/i },
  {
    id: 'sqli-tautology',
    category: 'sqli',
    pattern: /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  },
  { id: 'sqli-time-based', category: 'sqli', pattern: /\b(sleep|benchmark|pg_sleep)\s*\(/i },
  {
    id: 'sqli-stacked',
    category: 'sqli',
    pattern: /;\s*(drop|delete|update|insert|alter)\s+/i,
  },
  {
    id: 'sqli-schema-probe',
    category: 'sqli',
    pattern: /information_schema|sysobjects|xp_cmdshell/i,
  },
  {
    id: 'path-traversal',
    category: 'lfi',
    pattern: /(\.\.[/\\])|(%2e%2e[/\\])|(%2e%2e%2f)|(\/etc\/passwd)|(\/proc\/self)/i,
  },
  {
    id: 'php-shell-function',
    category: 'php_rce',
    pattern:
      /\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|base64_decode|create_function)\s*\(/i,
  },
  { id: 'php-open-tag', category: 'php_rce', pattern: /<\?php/i },
  { id: 'php-stream-wrapper', category: 'php_rce', pattern: /php:\/\/(filter|input|data)/i },
  {
    id: 'webshell-filename',
    category: 'php_rce',
    pattern: /\b(c99|r57|b374k|wso|alfa|shell)\.php\b/i,
  },
  {
    id: 'scanner-signature',
    category: 'scanner',
    pattern: /\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|nuclei)\b/i,
  },
]

const MAX_DECODE_ROUNDS = 2
const MAX_INSPECT_CHARS = 256_000

function decodeSafely(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function expand(value: string): string[] {
  const variants = [value]
  const plusAsSpace = value.replace(/\+/g, ' ')
  variants.push(plusAsSpace)

  let current = value
  for (let i = 0; i < MAX_DECODE_ROUNDS; i += 1) {
    const decoded = decodeSafely(current)
    if (decoded === current) break
    variants.push(decoded)
    variants.push(decoded.replace(/\+/g, ' '))
    current = decoded
  }
  return variants
}

function findRule(haystack: string): WafHit | null {
  for (const rule of WAF_RULES) {
    if (rule.pattern.test(haystack)) return { id: rule.id, category: rule.category }
  }
  return null
}

/**
 * Checks path, query and body. Body is only available in the Node route
 * handler — Next middleware cannot read it — so the route handler repeats the
 * path/query check as defence in depth.
 */
export function inspectRequest(input: {
  path: string
  query?: string
  body?: string
  userAgent?: string
}): WafResult {
  const body = (input.body ?? '').slice(0, MAX_INSPECT_CHARS)
  const chunks = [input.path, input.query ?? '', body, input.userAgent ?? ''].flatMap(expand)
  const rule = findRule(chunks.join('\n'))
  return rule ? { hit: true, rule } : { hit: false }
}
