import React from 'react';
import { useUser } from './user-context';

// Define permission types
export type Permission =
  | 'view_vendors'
  | 'view_security_scans'
  | 'manage_vendors'
  | 'delete_vendors'
  | 'add_vendors'
  | 'run_full_scans'
  | 'check_all_certifications'
  | 'view_certifications'
  | 'view_incidents'
  | 'view_pwn_monitor'
  | 'view_admin_features'
  | 'manage_access_management'
  | 'manage_additional_domains'
  | 'view_subdomains'
  | 'add_subdomains'
  | 'exclude_subdomains'
  | 'view_vendor_reports'
  | 'export_vendor_reports'
  | 'view_internal_breaches'
  | 'query_internal_breaches'
  | 'view_audit_logs'
  | 'view_portfolios'
  | 'create_portfolios'
  | 'manage_portfolios'
  | 'delete_portfolios'
  | 'view_api_keys'
  | 'manage_api_keys';

// Role-based permissions mapping (SSO role defaults when no Access Management assignment)
export const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  admin: [
    'view_vendors',
    'view_security_scans',
    'manage_vendors',
    'delete_vendors',
    'add_vendors',
    'run_full_scans',
    'check_all_certifications',
    'view_certifications',
    'view_incidents',
    'view_pwn_monitor',
    'view_admin_features',
    'manage_access_management',
    'manage_additional_domains',
    'view_subdomains',
    'add_subdomains',
    'exclude_subdomains',
    'view_vendor_reports',
    'export_vendor_reports',
    'view_internal_breaches',
    'query_internal_breaches',
    'view_audit_logs',
    'view_portfolios',
    'create_portfolios',
    'manage_portfolios',
    'delete_portfolios',
    'view_api_keys',
    'manage_api_keys',
  ],
  // SSO vendor-management group — vendor ops only (no admin routes / breaches)
  'vendor-management': [
    'view_vendors',
    'manage_vendors',
    'delete_vendors',
    'add_vendors',
    'view_subdomains',
    'add_subdomains',
    'exclude_subdomains',
    'manage_additional_domains',
    'view_vendor_reports',
    'export_vendor_reports',
    'view_certifications',
    'view_incidents',
    'view_pwn_monitor',
  ],
  // Extended: viewer + internal breaches
  'user-extended': [
    'view_vendors',
    'view_subdomains',
    'view_vendor_reports',
    'view_portfolios',
    'view_internal_breaches',
    'view_certifications',
    'view_incidents',
    'view_pwn_monitor',
  ],
  // Viewer: vendor management read, portfolios read; no scans/breaches/admin
  'user-basic': [
    'view_vendors',
    'view_subdomains',
    'view_vendor_reports',
    'view_portfolios',
    'view_certifications',
    'view_incidents',
    'view_pwn_monitor',
  ],
};

function effectivePermissionsFromUser(user: {
  role: string | null;
  permissions?: Permission[];
}): Permission[] {
  if (Array.isArray(user.permissions)) {
    return user.permissions;
  }
  if (!user.role) return [];
  return ROLE_PERMISSIONS[user.role] || [];
}

// Hook to check if user has specific permission
export const usePermission = (permission: Permission): boolean => {
  const user = useUser();
  if (!user.role && user.permissions.length === 0) return false;
  return effectivePermissionsFromUser(user).includes(permission);
};

// Hook to check multiple permissions (AND logic)
export const usePermissions = (permissions: Permission[]): boolean => {
  const user = useUser();
  const userPermissions = effectivePermissionsFromUser(user);
  if (!user.role && userPermissions.length === 0) return false;
  return permissions.every((permission) => userPermissions.includes(permission));
};

// Hook to check if user has any of the permissions (OR logic)
export const useAnyPermission = (permissions: Permission[]): boolean => {
  const user = useUser();
  const userPermissions = effectivePermissionsFromUser(user);
  if (!user.role && userPermissions.length === 0) return false;
  return permissions.some((permission) => userPermissions.includes(permission));
};

// Hook to get user role
export const useUserRole = (): string | null => {
  const { role } = useUser();
  return role;
};

// Hook to check if user is admin (SSO admin role — Access Management / write ops)
export const useIsAdmin = (): boolean => {
  const { role } = useUser();
  return role === 'admin';
};

// Hook to check if user can view plaintext passwords (internal breach access)
export const useCanViewPasswords = (): boolean => {
  return usePermission('view_internal_breaches');
};

// Hook to check if user is a basic vendor user
export const useIsUser = (): boolean => {
  const { role, permissionsFromAssignment } = useUser();
  if (permissionsFromAssignment) return false;
  return role === 'user-basic';
};

// Utility function to check permission without hook (for use outside React components)
export const hasPermission = (
  userRole: string | undefined,
  permission: Permission,
  assignedPermissions?: Permission[] | null,
): boolean => {
  if (Array.isArray(assignedPermissions)) {
    return assignedPermissions.includes(permission);
  }
  if (!userRole) return false;
  const permissions = ROLE_PERMISSIONS[userRole] || [];
  return permissions.includes(permission);
};

// Utility function to get all permissions for a role
export const getRolePermissions = (role: string): Permission[] => {
  return ROLE_PERMISSIONS[role] || [];
};

// Component wrapper for conditional rendering based on permissions
interface PermissionGateProps {
  permission?: Permission;
  permissions?: Permission[];
  requireAll?: boolean; // If true, requires ALL permissions; if false, requires ANY
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

export const PermissionGate: React.FC<PermissionGateProps> = ({
  permission,
  permissions = [],
  requireAll = true,
  fallback = null,
  children,
}) => {
  const user = useUser();
  const userPermissions = effectivePermissionsFromUser(user);

  if (!user.role && userPermissions.length === 0) {
    return React.createElement(React.Fragment, null, fallback);
  }

  let hasAccess = false;

  if (permission) {
    hasAccess = userPermissions.includes(permission);
  } else if (permissions.length > 0) {
    hasAccess = requireAll
      ? permissions.every((p) => userPermissions.includes(p))
      : permissions.some((p) => userPermissions.includes(p));
  }

  return hasAccess
    ? React.createElement(React.Fragment, null, children)
    : React.createElement(React.Fragment, null, fallback);
};

const rbac = {
  usePermission,
  usePermissions,
  useAnyPermission,
  useUserRole,
  useIsAdmin,
  useCanViewPasswords,
  useIsUser,
  hasPermission,
  getRolePermissions,
  PermissionGate,
};

export default rbac;
