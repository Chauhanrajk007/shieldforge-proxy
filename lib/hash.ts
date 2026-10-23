/** SHA-256 prefix only. Used for session_token_hash — never the raw value. */
export async function hashSecret(value: string): Promise<string> {
  if (!value) return ''
  const bytes = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16)
}
