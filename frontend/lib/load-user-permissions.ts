import { getInternalApiUrl } from '@/lib/internal-api-url';
import type { Permission } from '@/lib/rbac';
import { ROLE_PERMISSIONS } from '@/lib/rbac';
import type { UserRole } from '@/lib/auth-config';

const ALL_PERMISSIONS = new Set<string>(
  Object.values(ROLE_PERMISSIONS).flatMap((perms) => perms),
);

function sanitizePermissions(raw: unknown): Permission[] {
  if (!Array.isArray(raw)) return [];
  const out: Permission[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const perm = String(item || '').trim();
    if (!perm || !ALL_PERMISSIONS.has(perm) || seen.has(perm)) continue;
    seen.add(perm);
    out.push(perm as Permission);
  }
  return out;
}

export type LoadedUserPermissions = {
  /** When true, Access Management assignment overrides SSO role defaults. */
  hasAssignment: boolean;
  permissions: Permission[];
  source: 'assignment' | 'role_default' | 'fallback';
};

/**
 * Load effective permissions for a user from the Dashboard.
 * On failure, falls back to ROLE_PERMISSIONS[role] so the UI still works.
 */
export async function loadUserPermissions(opts: {
  email: string;
  role: UserRole | null;
  userId?: string;
  name?: string;
}): Promise<LoadedUserPermissions> {
  const email = opts.email.trim();
  const roleDefaults = opts.role ? ROLE_PERMISSIONS[opts.role] || [] : [];

  if (!email) {
    return {
      hasAssignment: false,
      permissions: roleDefaults,
      source: 'fallback',
    };
  }

  try {
    const response = await fetch(`${getInternalApiUrl()}/api/me/permissions`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Email': email,
        'X-User-Role': opts.role || '',
        'X-User-ID': opts.userId || email,
        'X-User-Name': opts.name || '',
      },
      cache: 'no-store',
    });

    if (!response.ok) {
      return {
        hasAssignment: false,
        permissions: roleDefaults,
        source: 'fallback',
      };
    }

    const data = (await response.json()) as {
      has_assignment?: boolean;
      source?: string;
      permissions?: unknown;
    };

    const permissions = sanitizePermissions(data.permissions);
    if (data.has_assignment) {
      return {
        hasAssignment: true,
        permissions,
        source: 'assignment',
      };
    }

    return {
      hasAssignment: false,
      permissions: permissions.length > 0 ? permissions : roleDefaults,
      source: 'role_default',
    };
  } catch {
    return {
      hasAssignment: false,
      permissions: roleDefaults,
      source: 'fallback',
    };
  }
}
