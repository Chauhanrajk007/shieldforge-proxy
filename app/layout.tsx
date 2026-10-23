import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ShieldForge Proxy — Control Room',
  description: 'Reverse proxy, rule-based WAF and async AI detection demo dashboard',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
