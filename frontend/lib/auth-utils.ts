/**
 * Auth utility helpers for SSO-based authentication.
 *
 * Session data is derived from the SSO JWT claims injected by middleware as
 * x-user-* request headers. Server components can read these via
 * next/headers; client components use the useUser() hook from user-context.
 */

import { headers } from 'next/headers';
import { ALLOWED_GROUPS, resolveRole } from './auth-config';
import type { UserInfo } from './user-context';

/**
 * Read the current user from the identity headers (server components only).
 * Returns a populated UserInfo object — role will be null if the user is
 * not in any allowed group (should not happen if middleware is correctly wired).
 */
export async function getServerUser(): Promise<UserInfo> {
  const headersList = await headers();
  const email = headersList.get('x-user-email') ?? '';
  const name = headersList.get('x-user-name') ?? undefined;
  const groupsHeader = headersList.get('x-user-groups') ?? '';
  const groups = groupsHeader ? groupsHeader.split(',').filter(Boolean) : [];
  const role = resolveRole(groups);
  return {
    email,
    name,
    groups,
    role,
    permissions: [],
    permissionsFromAssignment: false,
  };
}

/**
 * Returns true when the user has the admin role.
 */
export function isAdmin(user: UserInfo): boolean {
  return user.role === 'admin';
}

/**
 * Returns true when the user has exactly the specified role.
 */
export function hasRole(user: UserInfo, role: string): boolean {
  return user.role === role;
}

/**
 * Returns true when the user belongs to the named group.
 * Comparison is case-insensitive and trims whitespace.
 */
export function hasGroup(user: UserInfo, groupName: string): boolean {
  return user.groups.some(
    (g) => g.trim().toLowerCase() === groupName.trim().toLowerCase(),
  );
}

/**
 * Returns true when the user belongs to at least one of the named groups.
 */
export function hasAnyGroup(user: UserInfo, groupNames: string[]): boolean {
  return groupNames.some((name) => hasGroup(user, name));
}

/**
 * Returns true when the user can access admin features.
 */
export function canAccessAdmin(user: UserInfo): boolean {
  return isAdmin(user);
}

/**
 * Returns true when the user can perform vendor write operations
 * (admin or vendor-management).
 */
export function canWrite(user: UserInfo): boolean {
  return user.role === 'admin' || user.role === 'vendor-management';
}

/**
 * Returns true when the user is read-only (no vendor write role).
 */
export function isReadOnly(user: UserInfo): boolean {
  return !canWrite(user);
}

/**
 * Returns all allowed group names from configuration.
 */
export function getAllowedGroups(): string[] {
  return ALLOWED_GROUPS.map((g) => g.name);
}

/**
 * Returns group names that carry admin privileges.
 */
export function getAdminGroups(): string[] {
  return ALLOWED_GROUPS.filter((g) => g.role === 'admin').map((g) => g.name);
}

/**
 * Throws if the user is not authenticated (no role resolved).
 */
export function requireAuth(user: UserInfo): void {
  if (!user.role) {
    throw new Error('Authentication required');
  }
}

/**
 * Throws if the user does not have the admin role.
 */
export function requireAdmin(user: UserInfo): void {
  requireAuth(user);
  if (!isAdmin(user)) {
    throw new Error('Admin role required');
  }
}

/**
 * Throws if the user does not have the specified role.
 */
export function requireRole(user: UserInfo, role: string): void {
  requireAuth(user);
  if (!hasRole(user, role)) {
    throw new Error(`Role '${role}' required`);
  }
}

/**
 * Throws if the user is not a member of the specified group.
 */
export function requireGroup(user: UserInfo, groupName: string): void {
  requireAuth(user);
  if (!hasGroup(user, groupName)) {
    throw new Error(`Group membership '${groupName}' required`);
  }
}
