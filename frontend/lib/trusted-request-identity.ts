import type { NextRequest } from 'next/server';
import { verifySsoToken, extractSsoToken } from '@/lib/sso-auth';
import {
  ADMIN_GROUPS,
  ALL_ALLOWED_GROUP_NAMES,
  resolveRole,
} from '@/lib/auth-config';
import { isMockAuthEnabled } from '@/lib/auth-mode';

export type TrustedIdentity = {
  userId: string;
  email: string;
  name: string;
  groups: string;
  role: string;
};

/**
 * Same rules as middleware: prefer identity headers injected after SSO verification.
 * Fall back to verifying the SSO JWT header for direct/server calls.
 * Never trust client-supplied X-User-* headers unless middleware has already run.
 */
function getMiddlewareIdentity(request: NextRequest): TrustedIdentity | null {
  const userId = request.headers.get('x-user-id');
  const email = request.headers.get('x-user-email');
  if (!userId || !email) {
    return null;
  }

  return {
    userId,
    email,
    name: request.headers.get('x-user-name') ?? '',
    groups: request.headers.get('x-user-groups') ?? '',
    role: request.headers.get('x-user-role') ?? '',
  };
}

export async function getTrustedIdentity(
  request: NextRequest,
): Promise<TrustedIdentity | null> {
  if (isMockAuthEnabled) {
    const mockGroups = [ADMIN_GROUPS[0] ?? 'vendiant-admin'];
    const mockRole = resolveRole(mockGroups) ?? 'admin';
    return {
      userId: 'dev-mock-user',
      email: 'dev@localhost',
      name: 'Dev User',
      groups: mockGroups.join(','),
      role: mockRole,
    };
  }

  const middlewareIdentity = getMiddlewareIdentity(request);
  if (middlewareIdentity) {
    return middlewareIdentity;
  }

  const ssoJwt = extractSsoToken(request.headers);

  if (!ssoJwt) {
    return null;
  }

  const cfUser = await verifySsoToken(ssoJwt);
  if (!cfUser) {
    return null;
  }

  const normalizedUserGroups = cfUser.groups.map((g) => g.trim().toLowerCase());
  const normalizedAllowed = ALL_ALLOWED_GROUP_NAMES.map((g) => g.toLowerCase());
  const isAllowed = normalizedUserGroups.some((g) => normalizedAllowed.includes(g));

  if (!isAllowed) {
    return null;
  }

  const role = resolveRole(cfUser.groups);

  return {
    userId: cfUser.sub,
    email: cfUser.email,
    name: cfUser.name ?? '',
    groups: cfUser.groups.join(','),
    role: role ?? '',
  };
}

/** Headers the FastAPI backend expects for RBAC and audit (from verified identity only). */
export function userIdentityProxyHeaders(identity: TrustedIdentity): Record<string, string> {
  return {
    'X-User-ID': identity.userId,
    'X-User-Email': identity.email,
    'X-User-Name': identity.name,
    'X-User-Role': identity.role,
    'X-User-Groups': identity.groups,
  };
}

/**
 * Forward the caller's IP headers on server-side calls to the backend. Without
 * them the backend only sees this frontend pod as the TCP peer, so audit rows
 * record the proxy's IP instead of the user's. CF-Connecting-IP is set by a
 * Cloudflare edge when one is in front; otherwise X-Forwarded-For is used.
 */
export function clientIpProxyHeaders(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const name of ['CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP']) {
    const value = request.headers.get(name);
    if (value) headers[name] = value;
  }
  return headers;
}
