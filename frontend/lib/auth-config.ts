/**
 * SSO group-based RBAC configuration.
 *
 * Group names must match the groups claim your identity provider / SSO
 * gateway puts in the JWT. Override them at build time with
 * NEXT_PUBLIC_SSO_GROUP_ADMIN, NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT,
 * NEXT_PUBLIC_SSO_GROUP_USER and NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY.
 * Four roles are supported:
 *   - admin              → full read/write access, all admin routes, all breach data
 *   - vendor-management  → vendor CRUD + subdomain add/exclude (no admin routes / breaches)
 *   - user-extended      → read-only with internal breach visibility
 *   - user-basic         → most restricted read-only (no internal breaches)
 *
 * Access is granted only to groups explicitly listed in ALLOWED_GROUPS.
 * No prefix-based fallback — unrecognised groups are always denied.
 */

export type UserRole =
  | 'admin'
  | 'vendor-management'
  | 'user-extended'
  | 'user-basic';

export interface GroupConfig {
  name: string;
  role: UserRole;
  description: string;
}

export const ALLOWED_GROUPS: GroupConfig[] = [
  {
    name: process.env.NEXT_PUBLIC_SSO_GROUP_ADMIN || 'vendiant-admin',
    role: 'admin',
    description: 'Full administrative access — read + write, /admin routes, all breach data',
  },
  {
    name: process.env.NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT || 'vendiant-vendor-management',
    role: 'vendor-management',
    description:
      'Vendor management — add/edit/delete vendors and manage subdomain add/exclude',
  },
  {
    name: process.env.NEXT_PUBLIC_SSO_GROUP_USER || 'vendiant-user',
    role: 'user-extended',
    description: 'Extended read-only access — includes internal breach visibility',
  },
  {
    name: process.env.NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY || 'vendiant-vendors-only',
    role: 'user-basic',
    description: 'Most restricted read-only access — no internal breach data',
  },
];

/** Names of every group that carries admin privileges */
export const ADMIN_GROUPS: string[] = ALLOWED_GROUPS.filter(
  (g) => g.role === 'admin',
).map((g) => g.name);

/** Names of groups with extended user privileges (admin + user-extended) */
export const EXTENDED_GROUPS: string[] = ALLOWED_GROUPS.filter(
  (g) => g.role === 'admin' || g.role === 'user-extended',
).map((g) => g.name);

/** Names of groups that can perform vendor write operations */
export const VENDOR_WRITE_GROUPS: string[] = ALLOWED_GROUPS.filter(
  (g) => g.role === 'admin' || g.role === 'vendor-management',
).map((g) => g.name);

/** Names of all groups allowed to access the application */
export const ALL_ALLOWED_GROUP_NAMES: string[] = ALLOWED_GROUPS.map(
  (g) => g.name,
);

/**
 * Normalize group name for comparison (trim whitespace, lowercase).
 */
function normalizeGroupName(group: string): string {
  return group.trim().toLowerCase();
}

/**
 * Returns true when at least one of `userGroups` is in `allowedGroups`.
 * Comparison is case-insensitive and trims whitespace.
 * Only explicitly listed groups are accepted — no prefix fallback.
 */
export function hasGroupAccess(
  userGroups: string[],
  allowedGroups: string[] | readonly string[],
): boolean {
  if (!userGroups?.length) return false;
  const allowed = Array.from(allowedGroups).map(normalizeGroupName);
  return userGroups.some((g) => allowed.includes(normalizeGroupName(g)));
}

/**
 * Resolve the highest role for a user based on their groups.
 * Priority: admin > vendor-management > user-extended > user-basic
 * Comparison is case-insensitive and trims whitespace.
 * Only groups explicitly listed in ALLOWED_GROUPS are recognised.
 */
export function resolveRole(userGroups: string[]): UserRole | null {
  if (!userGroups?.length) return null;

  const normalizedUserGroups = userGroups.map(normalizeGroupName);

  // Walk in priority order
  const priority: UserRole[] = [
    'admin',
    'vendor-management',
    'user-extended',
    'user-basic',
  ];
  for (const role of priority) {
    for (const group of ALLOWED_GROUPS) {
      if (
        group.role === role &&
        normalizedUserGroups.includes(normalizeGroupName(group.name))
      ) {
        return role;
      }
    }
  }

  return null;
}

/** Returns true when the user has write permissions (admin or vendor-management) */
export function hasWritePermissions(userGroups: string[]): boolean {
  const role = resolveRole(userGroups);
  return role === 'admin' || role === 'vendor-management';
}
