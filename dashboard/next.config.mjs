/** @type {import('next').NextConfig} */

// Allow CSP connect-src to be extended via env for production deployments
const connectSrcExtra = process.env.CSP_CONNECT_SRC || "";

const nextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,

  // Compress responses — reduces payload sizes by ~60-70%
  compress: true,

  // Strict output for production builds
  typescript: { ignoreBuildErrors: false },
  eslint: { ignoreDuringBuilds: true },

  // Production-grade security headers
  async headers() {
    const connectSrc = [
      "'self'",
      "http://localhost:*",
      "ws://localhost:*",
      connectSrcExtra,
    ]
      .filter(Boolean)
      .join(" ");

    return [
      {
        source: "/(.*)",
        headers: [
          // Prevent MIME-type sniffing
          { key: "X-Content-Type-Options", value: "nosniff" },
          // Prevent clickjacking
          { key: "X-Frame-Options", value: "SAMEORIGIN" },
          // XSS protection for legacy browsers
          { key: "X-XSS-Protection", value: "1; mode=block" },
          // Referrer policy — send origin only on cross-origin
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          // Disable DNS prefetch leaking visited page info
          { key: "X-DNS-Prefetch-Control", value: "off" },
          // Permissions policy — restrict browser features
          {
            key: "Permissions-Policy",
            value:
              "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
          // Content Security Policy
          // unsafe-eval required by Recharts/D3 for dynamic path calculations
          // unsafe-inline required by Next.js for inline script bootstrapping
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob:",
              "font-src 'self' data:",
              `connect-src ${connectSrc}`,
              "frame-ancestors 'self'",
              "base-uri 'self'",
              "form-action 'self'",
              "object-src 'none'",
            ].join("; "),
          },
          // HSTS — enforce HTTPS (1 year, include subdomains)
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
        ],
      },
      {
        // Cache static assets aggressively
        source: "/_next/static/(.*)",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=31536000, immutable",
          },
        ],
      },
      {
        // API responses must never be cached by browser/proxies
        source: "/api/(.*)",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, no-cache, must-revalidate, proxy-revalidate",
          },
          { key: "Pragma", value: "no-cache" },
          { key: "Expires", value: "0" },
        ],
      },
    ];
  },
};

export default nextConfig;
