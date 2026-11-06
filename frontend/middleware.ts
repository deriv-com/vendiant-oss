import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifySsoToken, extractSsoToken } from './lib/sso-auth';
import {
  ADMIN_GROUPS,
  ALL_ALLOWED_GROUP_NAMES,
  hasGroupAccess,
  resolveRole,
} from './lib/auth-config';
import { isMockAuthEnabled } from './lib/auth-mode';

/** Paths that bypass SSO JWT verification entirely */
const PUBLIC_PREFIXES = [
  '/_next/static',
  '/_next/image',
  '/favicon',
  '/public/',
  '/unauthorized',
  '/api/health',
];

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

/** Admin-only protected routes */
const ADMIN_ONLY_ROUTES = [
  '/admin',
  '/settings',
  '/users',
  '/api/admin',
  '/api/audit-logs',
  '/api/api-keys',
];

/** Routes that require at minimum the user-extended role */
const EXTENDED_ROUTES: string[] = [];

/**
 * Per-request Content-Security-Policy (VND-006). Inline scripts only run if
 * they carry this request's nonce, so the policy needs no 'unsafe-inline' for
 * scripts. Next.js reads the nonce from the request's CSP header and stamps
 * its own scripts; app/layout.tsx reads x-nonce for the theme script.
 * Inline styles stay allowed: components use React style={{}} attributes.
 */
function buildCsp(nonce: string): string {
  const isDev = process.env.NODE_ENV === 'development';
  const connectSrc = buildConnectSrcDirective(isDev);
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ''}`,
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
    "font-src 'self' data: https://cdnjs.cloudflare.com",
    "img-src 'self' https: data: blob:",
    connectSrc,
    "frame-src 'self'",
    "frame-ancestors 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

function parseOriginCandidate(raw: string): string | null {
  const value = raw.trim();
  if (!value) return null;
  try {
    const parsed = new URL(value);
    return parsed.origin;
  } catch {
    return null;
  }
}

function buildConnectSrcDirective(isDev: boolean): string {
  const sources = new Set<string>(["'self'"]);

  // Explicitly allow known runtime origins only; avoid blanket https: in connect-src.
  const envCandidates = [
    process.env.NEXT_PUBLIC_API_URL,
    process.env.NEXT_PUBLIC_BASE_URL,
  ];

  for (const candidate of envCandidates) {
    if (!candidate) continue;
    const origin = parseOriginCandidate(candidate);
    if (origin) {
      sources.add(origin);
    }
  }

  if (isDev) {
    sources.add('ws:');
  }

  return `connect-src ${Array.from(sources).join(' ')}`;
}

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const nonce = btoa(crypto.randomUUID());
  const csp = buildCsp(nonce);

  // Request headers every downstream handler sees; the client cannot supply
  // its own x-nonce because it is overwritten here.
  const baseHeaders = new Headers(request.headers);
  baseHeaders.set('x-nonce', nonce);
  baseHeaders.set('Content-Security-Policy', csp);

  const pass = (headers: Headers): NextResponse => {
    const response = NextResponse.next({ request: { headers } });
    response.headers.set('Content-Security-Policy', csp);
    return response;
  };

  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return pass(baseHeaders);
  }

  // ── 0. Mock auth (local dev only) ───────────────────────────────────────────
  if (isMockAuthEnabled) {
    const mockGroups = [ADMIN_GROUPS[0] ?? 'vendiant-admin'];
    const mockRole = resolveRole(mockGroups) ?? 'admin';

    // Route-level RBAC still applies even in mock mode.
    const isAdminRoute = ADMIN_ONLY_ROUTES.some((r) => pathname.startsWith(r));
    const isExtendedRoute = EXTENDED_ROUTES.some((r) => pathname.startsWith(r));

    if (isAdminRoute && mockRole !== 'admin') {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }
    if (isExtendedRoute && mockRole === 'user-basic') {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }

    const reqHeaders = new Headers(baseHeaders);
    reqHeaders.set('x-user-id', 'dev-mock-user');
    reqHeaders.set('x-user-email', 'dev@localhost');
    reqHeaders.set('x-user-name', 'Dev User');
    reqHeaders.set('x-user-groups', mockGroups.join(','));
    reqHeaders.set('x-user-role', mockRole);

    return pass(reqHeaders);
  }

  // ── 1. Extract the SSO JWT forwarded by the gateway ─────────────────────────
  const ssoJwt = extractSsoToken(request.headers);

  if (!ssoJwt) {
    // The SSO gateway is the outer gate; a missing JWT here means something
    // slipped through (e.g. direct internal access). Deny hard.
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  // ── 2. Verify JWT via JWKS ──────────────────────────────────────────────────
  const cfUser = await verifySsoToken(ssoJwt);

  if (!cfUser) {
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  // ── 3. Group membership check ───────────────────────────────────────────────
  const normalizedUserGroups = cfUser.groups.map((g) => g.trim().toLowerCase());
  const normalizedAllowed = ALL_ALLOWED_GROUP_NAMES.map((g) => g.toLowerCase());
  const isAllowed = normalizedUserGroups.some((g) => normalizedAllowed.includes(g));

  if (!isAllowed) {
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  // ── 4. Resolve role ─────────────────────────────────────────────────────────
  const role = resolveRole(cfUser.groups);

  // ── 5. Route-level RBAC ─────────────────────────────────────────────────────
  const isAdminRoute = ADMIN_ONLY_ROUTES.some((r) => pathname.startsWith(r));
  const isExtendedRoute = EXTENDED_ROUTES.some((r) => pathname.startsWith(r));

  // Admin routes require membership in the admin SSO group (not just a resolved role)
  const isInAdminGroup = hasGroupAccess(cfUser.groups, ADMIN_GROUPS);
  if (isAdminRoute && (role !== 'admin' || !isInAdminGroup)) {
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  if (isExtendedRoute && role === 'user-basic') {
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  // ── 6. Inject user identity headers for downstream consumers ────────────────
  // These are read by:
  //   • Next.js server components (via next/headers) → forwarded to UserProvider
  //   • FastAPI backend (via next.config.js rewrites) → enforces its own RBAC
  const requestHeaders = new Headers(baseHeaders);
  requestHeaders.set('x-user-id', cfUser.sub);
  requestHeaders.set('x-user-email', cfUser.email);
  requestHeaders.set('x-user-name', cfUser.name ?? '');
  requestHeaders.set('x-user-groups', cfUser.groups.join(','));
  requestHeaders.set('x-user-role', role ?? '');

  return pass(requestHeaders);
}

export const config = {
  matcher: [
    /*
     * Match all paths except Next.js internals and static assets.
     * Public paths (/_next/*, /favicon*, etc.) are short-circuited inside
     * the middleware function itself so they never reach the JWT check.
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
