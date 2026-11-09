/**
 * Single sign-on JWT verification.
 *
 * Vendiant expects to sit behind an SSO gateway / identity-aware proxy that
 * authenticates users against your identity provider and forwards a signed
 * JWT with every request (Cloudflare Access, oauth2-proxy, Pomerium, Google
 * IAP, Authelia, Teleport, ... all work this way). The JWT is verified here
 * with the gateway's public JWKS; no IdP client secrets are needed.
 *
 * Required env (see docs/AUTHENTICATION.md):
 *   SSO_JWKS_URL       — JWKS endpoint of the gateway, e.g.
 *                        https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
 *   SSO_ISSUER         — expected `iss` claim
 *   SSO_AUDIENCE       — expected `aud` claim
 * Optional:
 *   SSO_JWT_HEADER     — request header carrying the JWT
 *                        (default "cf-access-jwt-assertion")
 *   SSO_GROUPS_CLAIM   — claim holding the user's groups (default "groups";
 *                        "groups", "group", "roles", "custom.group" and
 *                        "custom.groups" are always tried as fallbacks)
 */

import { createRemoteJWKSet, jwtVerify } from 'jose';

export interface SsoUser {
  email: string;
  sub: string;
  name?: string;
  groups: string[];
  iat?: number;
  exp?: number;
}

/** Backwards-compatible alias. */
export type CloudflareUser = SsoUser;

export const SSO_JWT_HEADER = (process.env.SSO_JWT_HEADER || 'cf-access-jwt-assertion').toLowerCase();

let JWKS: ReturnType<typeof createRemoteJWKSet> | null = null;

/**
 * Derive a human-readable display name from an email address.
 * e.g. "jane.doe@example.com" → "Jane Doe"
 * Falls back to the local part if no separators are found.
 */
function deriveNameFromEmail(email: string): string {
  const local = email.split('@')[0] ?? email;
  return local
    .split(/[._\-+]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

function readClaim(payload: Record<string, unknown>, path: string): unknown {
  let cur: unknown = payload;
  for (const part of path.split('.')) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** Read the SSO JWT from an incoming request's headers. */
export function extractSsoToken(headers: Headers): string | null {
  const raw = headers.get(SSO_JWT_HEADER) || headers.get('cf-access-jwt-assertion');
  if (!raw) return null;
  // Support "Authorization: Bearer <jwt>" style headers too.
  return raw.replace(/^Bearer\s+/i, '').trim() || null;
}

/**
 * Verify an SSO JWT and return structured user info.
 * Returns `null` on any verification failure — treat as unauthenticated.
 */
export async function verifySsoToken(token: string): Promise<SsoUser | null> {
  const JWKS_URL = process.env.SSO_JWKS_URL;
  const ISSUER = process.env.SSO_ISSUER;
  const AUD = process.env.SSO_AUDIENCE;

  if (!JWKS_URL || !ISSUER || !AUD) {
    console.error('[AUTH] Missing SSO_JWKS_URL, SSO_ISSUER or SSO_AUDIENCE');
    return null;
  }

  if (!JWKS) {
    try {
      JWKS = createRemoteJWKSet(new URL(JWKS_URL));
    } catch {
      console.error('[AUTH] Failed to create JWKS: invalid SSO_JWKS_URL');
      return null;
    }
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: ISSUER,
      audience: AUD,
    });

    const claims = payload as Record<string, unknown>;
    const configuredClaim = process.env.SSO_GROUPS_CLAIM || 'groups';
    const candidates = [configuredClaim, 'groups', 'group', 'roles', 'custom.group', 'custom.groups'];
    let rawGroups: unknown = [];
    for (const c of candidates) {
      const v = readClaim(claims, c);
      if (v !== undefined && v !== null && v !== '') {
        rawGroups = v;
        break;
      }
    }
    const groups = Array.isArray(rawGroups)
      ? rawGroups
      : typeof rawGroups === 'string'
        ? rawGroups.split(/[ ,]+/)
        : [rawGroups];
    const validGroups = groups.filter((g): g is string => typeof g === 'string' && g.length > 0);

    const email = (claims['email'] as string) || 'unknown';

    // Display name may be at the root, under a custom block, or split in given/family parts.
    const custom = claims['custom'] as Record<string, unknown> | undefined;
    const rawName =
      (claims['name'] as string | undefined) ?? (custom?.['name'] as string | undefined);
    const givenName =
      (claims['given_name'] as string | undefined) ?? (custom?.['givenName'] as string | undefined);
    const surName =
      (claims['family_name'] as string | undefined) ?? (custom?.['surName'] as string | undefined);

    const resolvedName = (() => {
      if (rawName?.trim()) return rawName.trim();
      const full = [givenName, surName].filter(Boolean).join(' ');
      if (full) return full;
      return deriveNameFromEmail(email);
    })();

    return {
      email,
      sub: (claims['sub'] as string) || 'unknown',
      name: resolvedName,
      groups: validGroups,
      iat: typeof payload.iat === 'number' ? payload.iat : undefined,
      exp: typeof payload.exp === 'number' ? payload.exp : undefined,
    };
  } catch {
    // Do NOT log the token — it may contain PII
    console.error('[AUTH] SSO JWT verification failed');
    return null;
  }
}

/** Backwards-compatible alias. */
export const verifyCloudflareToken = verifySsoToken;
