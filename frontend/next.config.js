/** @type {import('next').NextConfig} */

// Public origin of the dashboard. Set CORS_ACCESS_CONTROL_ALLOW_ORIGIN (or
// NEXT_PUBLIC_BASE_URL) to your deployment URL.
const corsAllowOrigin =
  process.env.CORS_ACCESS_CONTROL_ALLOW_ORIGIN ||
  process.env.NEXT_PUBLIC_BASE_URL ||
  (process.env.NODE_ENV === 'production' ? 'http://localhost:8081' : 'http://localhost:3005');

const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  outputFileTracingRoot: __dirname,
  images: {
    domains: [
      'www.google.com',
      'favicons.githubusercontent.com',
      'api.faviconkit.com',
      'via.placeholder.com',
      'www.gravatar.com',
    ],
  },
  // CORS headers applied to all /api/* responses as a defence-in-depth layer.
  // The catch-all App Router handler (app/api/[...path]/route.ts) also sets
  // these headers directly; its values take precedence over these.
  async headers() {
    const corsHeaders = [
      { key: 'Access-Control-Allow-Origin', value: corsAllowOrigin },
      { key: 'Access-Control-Allow-Methods', value: 'GET,OPTIONS,PATCH,DELETE,POST,PUT' },
      {
        key: 'Access-Control-Allow-Headers',
        value:
          'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version',
      },
    ];

    return [
      { source: '/api/vendors/:path*', headers: corsHeaders },
      { source: '/api/dashboard/:path*', headers: corsHeaders },
      { source: '/api/subdomains/:path*', headers: corsHeaders },
      { source: '/api/vulnerabilities/:path*', headers: corsHeaders },
      { source: '/api/reputation/:path*', headers: corsHeaders },
      { source: '/api/dns/:path*', headers: corsHeaders },
      { source: '/api/network/:path*', headers: corsHeaders },
      { source: '/api/encryption/:path*', headers: corsHeaders },
      { source: '/api/reports/:path*', headers: corsHeaders },
      { source: '/api/incidents/:path*', headers: corsHeaders },
      { source: '/api/certifications/:path*', headers: corsHeaders },
      { source: '/api/breaches/:path*', headers: corsHeaders },
      { source: '/api/analytics/:path*', headers: corsHeaders },
    ];
  },
};

module.exports = nextConfig;
