'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import type { UserRole } from './auth-config';
import type { Permission } from './rbac';
import { ROLE_PERMISSIONS } from './rbac';

export interface UserInfo {
  email: string;
  name?: string;
  /** SSO subject identifier — used as X-User-ID for audit logging */
  sub?: string;
  groups: string[];
  role: UserRole | null;
  /**
   * Effective permissions for UI gates.
   * When ``permissionsFromAssignment`` is true these come from Access Management;
   * otherwise they are the SSO role defaults (or empty when unauthenticated).
   */
  permissions: Permission[];
  /** True when an active Access Management row overrides role defaults. */
  permissionsFromAssignment: boolean;
}

const defaultUser: UserInfo = {
  email: '',
  groups: [],
  role: null,
  permissions: [],
  permissionsFromAssignment: false,
};

const UserContext = createContext<UserInfo>(defaultUser);

/**
 * Consume the current signed-in user.
 * Must be used inside <UserProvider> (i.e. within the root layout).
 */
export function useUser(): UserInfo {
  return useContext(UserContext);
}

interface UserProviderProps {
  user: UserInfo;
  children: ReactNode;
}

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

/**
 * Client-side provider that exposes the SSO user info to the React tree.
 * Starts from server-hydrated identity/permissions, then re-fetches
 * /api/me/permissions on mount and window focus so Access Management
 * changes apply without requiring a full reload.
 */
export function UserProvider({ user, children }: UserProviderProps) {
  const [current, setCurrent] = useState<UserInfo>(user);

  // Keep in sync if the server sends a new user (e.g. full navigation).
  useEffect(() => {
    setCurrent(user);
  }, [user]);

  const refreshPermissions = useCallback(async () => {
    if (!user.email) return;
    try {
      const res = await fetch('/api/me/permissions', {
        method: 'GET',
        cache: 'no-store',
      });
      if (!res.ok) return;
      const data = (await res.json()) as {
        has_assignment?: boolean;
        permissions?: unknown;
      };
      const permissions = sanitizePermissions(data.permissions);
      if (data.has_assignment) {
        setCurrent((prev) => ({
          ...prev,
          permissions,
          permissionsFromAssignment: true,
        }));
        return;
      }
      const roleDefaults = user.role ? ROLE_PERMISSIONS[user.role] || [] : [];
      setCurrent((prev) => ({
        ...prev,
        permissions: permissions.length > 0 ? permissions : roleDefaults,
        permissionsFromAssignment: false,
      }));
    } catch {
      // Keep last known permissions on refresh failure.
    }
  }, [user.email, user.role]);

  useEffect(() => {
    void refreshPermissions();
    const onFocus = () => {
      void refreshPermissions();
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [refreshPermissions]);

  return <UserContext.Provider value={current}>{children}</UserContext.Provider>;
}

/**
 * Redirect the user to the SSO gateway's logout endpoint
 * (NEXT_PUBLIC_SSO_LOGOUT_URL, e.g. https://<team>.cloudflareaccess.com/cdn-cgi/access/logout
 * or https://your-host/oauth2/sign_out for oauth2-proxy). The gateway clears its
 * session; the user re-authenticates with the identity provider on the next visit.
 */
export function signOut(): void {
  const logoutUrl = process.env.NEXT_PUBLIC_SSO_LOGOUT_URL;
  if (logoutUrl) {
    window.location.href = logoutUrl;
  } else {
    // Fallback for local dev (no SSO gateway in front)
    window.location.href = '/';
  }
}
