import { apiRequest } from './api-client';

export interface IamEmployee {
  name: string;
  email: string;
}

export interface RoleMember {
  email: string;
  name: string | null;
  updated_at?: string | null;
}

export interface DashboardRole {
  id: number;
  name: string;
  slug: string;
  is_system: boolean;
  permissions: string[];
  member_count: number;
  members: RoleMember[];
  created_by_email: string | null;
  created_by_name: string | null;
  created_at: string | null;
  updated_at: string | null;
}

/** Load the user directory (name + email) for the Access Management picker. */
export async function listIamUsers(): Promise<IamEmployee[]> {
  const res = await apiRequest('/api/admin/directory/users');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail =
      (err as { detail?: string }).detail ||
      (err as { message?: string }).message ||
      (err as { error?: string }).error ||
      'User directory list failed';
    throw new Error(detail);
  }
  const data = await res.json();
  return data.employees ?? [];
}

/** Load all Access Management roles. */
export async function listRoles(): Promise<DashboardRole[]> {
  const res = await apiRequest('/api/admin/roles');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to load roles');
  }
  const data = await res.json();
  return data.roles ?? [];
}

/** Create a custom role. */
export async function createRole(payload: {
  name: string;
  permissions: string[];
}): Promise<DashboardRole> {
  const res = await apiRequest('/api/admin/roles', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to create role');
  }
  const data = await res.json();
  return data.role;
}

/** Update a role's name and/or permissions. */
export async function updateRole(
  roleId: number,
  payload: { name?: string; permissions?: string[] },
): Promise<DashboardRole> {
  const res = await apiRequest(`/api/admin/roles/${roleId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to update role');
  }
  const data = await res.json();
  return data.role;
}

/** Delete a custom role. */
export async function deleteRole(roleId: number): Promise<void> {
  const res = await apiRequest(`/api/admin/roles/${roleId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to delete role');
  }
}

/** Replace members assigned to a role. */
export async function setRoleMembers(
  roleId: number,
  members: { email: string; name?: string }[],
): Promise<DashboardRole> {
  const res = await apiRequest(`/api/admin/roles/${roleId}/members`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ members }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || 'Failed to update members');
  }
  const data = await res.json();
  return data.role;
}
