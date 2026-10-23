import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // The proxy route reads the body for the rule-based WAF and forwards a
  // streamed upstream response, so it must stay on the Node runtime.
  poweredByHeader: false,
  reactStrictMode: true,
  // Do not let Next 308-normalise `/t/shop/` before middleware/WAF runs.
  skipTrailingSlashRedirect: true,
}

export default nextConfig
