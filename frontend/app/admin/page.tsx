'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Layout from '../../components/Layout';
import { useIsAdmin, usePermission, ROLE_PERMISSIONS, type Permission } from '../../lib/rbac';
import { ADMIN_GROUPS, hasGroupAccess } from '../../lib/auth-config';
import { useUser } from '../../lib/user-context';
import {
  listIamUsers,
  listRoles,
  createRole,
  updateRole,
  deleteRole,
  setRoleMembers,
  type IamEmployee,
  type DashboardRole,
} from '../../lib/admin-api';

type AccessLevel = 'none' | 'read' | 'write';
type PageView = 'roles' | 'users';

interface AccessRow {
  id: string;
  label: string;
  read: Permission[];
  write: Permission[];
  levels?: AccessLevel[];
  levelLabels?: Partial<Record<AccessLevel, string>>;
}

interface AccessSection {
  title: string;
  rows: AccessRow[];
}

interface AssignedUser {
  email: string;
  name: string;
  roleId: number;
  roleName: string;
  roleSlug: string;
  isSystem: boolean;
  updatedAt: string | null;
}

const ACCESS_SECTIONS: AccessSection[] = [
  {
    title: 'Vendor Management',
    rows: [
      {
        id: 'vendors',
        label: 'Vendors',
        // Subdomain access follows vendors (not shown as its own row):
        // Read  → view vendors + view subdomains
        // Write → full vendor CRUD + add/exclude subdomains + additional domains
        read: ['view_vendors', 'view_subdomains'],
        write: [
          'view_vendors',
          'manage_vendors',
          'add_vendors',
          'delete_vendors',
          'view_subdomains',
          'add_subdomains',
          'exclude_subdomains',
          'manage_additional_domains',
        ],
      },
      {
        id: 'vendor_reports',
        label: 'Vendor reports',
        read: ['view_vendor_reports'],
        write: ['view_vendor_reports', 'export_vendor_reports'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
    ],
  },
  {
    title: 'Vendor Risk',
    rows: [
      {
        id: 'security_scans',
        label: 'Security scans',
        read: ['view_security_scans'],
        write: ['view_security_scans', 'run_full_scans'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
      {
        id: 'certifications',
        label: 'Certifications',
        read: ['view_certifications', 'check_all_certifications'],
        write: ['view_certifications', 'check_all_certifications'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
      {
        id: 'incidents',
        label: 'News & Incidents',
        read: ['view_incidents'],
        write: ['view_incidents'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
      {
        id: 'pwn_monitor',
        label: 'Pwn Monitor',
        read: ['view_pwn_monitor'],
        write: ['view_pwn_monitor'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
    ],
  },
  {
    title: 'Internal Breaches',
    rows: [
      {
        id: 'breach-monitor',
        label: 'Breach Monitor',
        read: ['view_internal_breaches'],
        write: ['view_internal_breaches', 'query_internal_breaches'],
      },
    ],
  },
  {
    title: 'Portfolios',
    rows: [
      {
        id: 'portfolios',
        label: 'Portfolios',
        read: ['view_portfolios'],
        write: [
          'view_portfolios',
          'create_portfolios',
          'manage_portfolios',
          'delete_portfolios',
        ],
      },
    ],
  },
  {
    title: 'Administration',
    rows: [
      {
        id: 'api_keys',
        label: 'API Keys',
        read: ['view_api_keys'],
        write: ['view_api_keys', 'manage_api_keys'],
      },
      {
        id: 'access_management',
        label: 'Access Management',
        read: ['view_admin_features'],
        write: ['view_admin_features', 'manage_access_management'],
      },
      {
        id: 'audit_logs',
        label: 'Audit Logs',
        read: ['view_audit_logs'],
        write: ['view_audit_logs'],
        levels: ['none', 'write'],
        levelLabels: { write: 'Access' },
      },
    ],
  },
];

const ALL_ROWS = ACCESS_SECTIONS.flatMap((s) => s.rows);
const TOTAL_FEATURE_ROWS = ALL_ROWS.length;

const DEFAULT_ACCESS_LEVELS: { value: AccessLevel; label: string }[] = [
  { value: 'none', label: 'No Access' },
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
];

function levelsForRow(row: AccessRow): { value: AccessLevel; label: string }[] {
  const allowed = row.levels ?? (['none', 'read', 'write'] as AccessLevel[]);
  return DEFAULT_ACCESS_LEVELS.filter((opt) => allowed.includes(opt.value)).map((opt) => ({
    value: opt.value,
    label: row.levelLabels?.[opt.value] ?? opt.label,
  }));
}

function getRowLevel(row: AccessRow, draft: Set<Permission>): AccessLevel {
  const writeHit = row.write.length > 0 && row.write.every((p) => draft.has(p));
  const readHit = row.read.length > 0 && row.read.every((p) => draft.has(p));
  const readEqualsWrite =
    row.read.length > 0 &&
    row.read.length === row.write.length &&
    row.read.every((p) => row.write.includes(p));
  const allowed = row.levels;

  let level: AccessLevel = 'none';
  if (writeHit && readEqualsWrite) {
    level =
      allowed && !allowed.includes('read') && allowed.includes('write')
        ? 'write'
        : 'read';
  } else if (writeHit) {
    level = 'write';
  } else if (readHit) {
    level = 'read';
  } else if (row.write.some((p) => draft.has(p))) {
    level = 'write';
  } else if (row.read.some((p) => draft.has(p))) {
    level = 'read';
  }

  if (
    level === 'read' &&
    allowed &&
    !allowed.includes('read') &&
    allowed.includes('write')
  ) {
    return 'write';
  }
  return level;
}

function applyRowLevel(
  row: AccessRow,
  level: AccessLevel,
  draft: Set<Permission>,
): Set<Permission> {
  const next = new Set(draft);
  for (const p of [...row.read, ...row.write]) next.delete(p);
  if (level === 'read') {
    for (const p of row.read) next.add(p);
  } else if (level === 'write') {
    for (const p of row.write) next.add(p);
  }
  return next;
}

/** Keep subdomain permissions aligned with the Vendors access level (no separate UI row). */
function syncSubdomainsWithVendors(draft: Set<Permission>): Set<Permission> {
  const vendorsRow = ALL_ROWS.find((r) => r.id === 'vendors');
  if (!vendorsRow) return draft;
  const level = getRowLevel(vendorsRow, draft);
  return applyRowLevel(vendorsRow, level, draft);
}

function levelsFromDraft(draft: Set<Permission>): Record<string, AccessLevel> {
  const levels: Record<string, AccessLevel> = {};
  for (const row of ALL_ROWS) levels[row.id] = getRowLevel(row, draft);
  return levels;
}

/** Count Access Management feature rows that are not No Access. */
function countEnabledFeatures(perms: Iterable<string>): number {
  const draft = new Set(perms as Permission[]);
  return ALL_ROWS.filter((row) => getRowLevel(row, draft) !== 'none').length;
}

function emptyLevels(): Record<string, AccessLevel> {
  const levels: Record<string, AccessLevel> = {};
  for (const row of ALL_ROWS) levels[row.id] = 'none';
  return levels;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return iso;
  }
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return (name.slice(0, 2) || '?').toUpperCase();
}

function roleTone(role: Pick<DashboardRole, 'slug' | 'is_system'>): string {
  if (role.slug === 'admin') return 'admin';
  if (role.slug === 'user-extended') return 'extended';
  if (role.slug === 'user-basic') return 'viewer';
  return 'custom';
}

function avatarHue(seed: string): string {
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) hash = (hash * 31 + seed.charCodeAt(i)) | 0;
  const hues = [12, 175, 210, 265, 320, 145];
  return `hsl(${hues[Math.abs(hash) % hues.length]} 62% 42%)`;
}

const AdminManagementPage: React.FC = () => {
  const isAdminRole = useIsAdmin();
  const { groups } = useUser();
  const canViewAdminFeatures = usePermission('view_admin_features');
  const canManageRoles = usePermission('manage_access_management');
  const canAccessPage =
    isAdminRole && hasGroupAccess(groups, ADMIN_GROUPS) && canViewAdminFeatures;

  const [isDarkMode, setIsDarkMode] = useState(false);
  const [view, setView] = useState<PageView>('roles');
  const [employees, setEmployees] = useState<IamEmployee[]>([]);
  const [roles, setRoles] = useState<DashboardRole[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [search, setSearch] = useState('');

  const [modalOpen, setModalOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<DashboardRole | null>(null);
  const [roleName, setRoleName] = useState('');
  const [draft, setDraft] = useState<Set<Permission>>(new Set());
  const [rowLevels, setRowLevels] = useState<Record<string, AccessLevel>>(emptyLevels);
  const [selectedMembers, setSelectedMembers] = useState<
    { email: string; name: string }[]
  >([]);
  const [memberSearch, setMemberSearch] = useState('');
  const [memberDropdownOpen, setMemberDropdownOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [assigningEmail, setAssigningEmail] = useState<string | null>(null);

  const memberDropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const check = () => setIsDarkMode(document.body.classList.contains('dark-mode'));
    check();
    const observer = new MutationObserver(check);
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!memberDropdownOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (!memberDropdownRef.current?.contains(e.target as Node)) {
        setMemberDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [memberDropdownOpen]);

  const reload = useCallback(async () => {
    setLoadingList(true);
    setLoadError('');
    try {
      const [emps, roleList] = await Promise.all([listIamUsers(), listRoles()]);
      setEmployees(emps);
      setRoles(roleList);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoadingList(false);
    }
  }, []);

  useEffect(() => {
    if (!canAccessPage) return;
    void reload();
  }, [canAccessPage, reload]);

  const flashSuccess = (msg: string) => {
    setSuccessMessage(msg);
    window.setTimeout(() => setSuccessMessage(''), 2800);
  };

  const assignedUsers = useMemo<AssignedUser[]>(() => {
    const rows: AssignedUser[] = [];
    for (const role of roles) {
      for (const m of role.members) {
        rows.push({
          email: m.email.toLowerCase(),
          name: m.name || m.email,
          roleId: role.id,
          roleName: role.name,
          roleSlug: role.slug,
          isSystem: role.is_system,
          updatedAt: m.updated_at ?? role.updated_at,
        });
      }
    }
    return rows.sort((a, b) => a.name.localeCompare(b.name));
  }, [roles]);

  const filteredRoles = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return roles;
    return roles.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.slug.toLowerCase().includes(q) ||
        r.members.some(
          (m) =>
            m.email.toLowerCase().includes(q) ||
            (m.name ?? '').toLowerCase().includes(q),
        ),
    );
  }, [roles, search]);

  const filteredUsers = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return assignedUsers;
    return assignedUsers.filter(
      (u) =>
        u.name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.roleName.toLowerCase().includes(q),
    );
  }, [assignedUsers, search]);

  const openCreate = () => {
    if (!canManageRoles) return;
    setEditingRole(null);
    setRoleName('');
    setDraft(new Set());
    setRowLevels(emptyLevels());
    setSelectedMembers([]);
    setMemberSearch('');
    setMemberDropdownOpen(false);
    setSaveError('');
    setModalOpen(true);
  };

  const openEdit = (role: DashboardRole) => {
    const perms = syncSubdomainsWithVendors(
      new Set<Permission>(role.permissions as Permission[]),
    );
    setEditingRole(role);
    setRoleName(role.name);
    setDraft(perms);
    setRowLevels(levelsFromDraft(perms));
    setSelectedMembers(
      role.members.map((m) => ({
        email: m.email.toLowerCase(),
        name: m.name || m.email,
      })),
    );
    setMemberSearch('');
    setMemberDropdownOpen(false);
    setSaveError('');
    setModalOpen(true);
  };

  const closeModal = () => {
    if (saving) return;
    setModalOpen(false);
    setEditingRole(null);
    setMemberDropdownOpen(false);
    setSaveError('');
  };

  const applySystemPreset = (slug: 'admin' | 'user-extended' | 'user-basic') => {
    if (!canManageRoles) return;
    const perms = syncSubdomainsWithVendors(
      new Set<Permission>((ROLE_PERMISSIONS[slug] ?? []) as Permission[]),
    );
    setDraft(perms);
    setRowLevels(levelsFromDraft(perms));
  };

  const setAccessLevel = (row: AccessRow, level: AccessLevel) => {
    if (!canManageRoles) return;
    setRowLevels((prev) => ({ ...prev, [row.id]: level }));
    setDraft((prev) => applyRowLevel(row, level, prev));
  };

  const addMember = (emp: IamEmployee) => {
    if (!canManageRoles) return;
    const email = emp.email.toLowerCase();
    setSelectedMembers((prev) => {
      if (prev.some((m) => m.email === email)) return prev;
      return [...prev, { email, name: emp.name }];
    });
    setMemberSearch('');
    setMemberDropdownOpen(false);
  };

  const removeMember = (email: string) => {
    if (!canManageRoles) return;
    setSelectedMembers((prev) => prev.filter((m) => m.email !== email));
  };

  const memberOptions = useMemo(() => {
    const selected = new Set(selectedMembers.map((m) => m.email));
    const q = memberSearch.trim().toLowerCase();
    return employees
      .filter((e) => !selected.has(e.email.toLowerCase()))
      .filter(
        (e) =>
          !q ||
          e.name.toLowerCase().includes(q) ||
          e.email.toLowerCase().includes(q),
      )
      .slice(0, 40);
  }, [employees, memberSearch, selectedMembers]);

  const handleSave = async () => {
    if (!canManageRoles) return;
    const name = roleName.trim();
    if (name.length < 2) {
      setSaveError('Role name must be at least 2 characters');
      return;
    }
    setSaving(true);
    setSaveError('');
    try {
      const permissions = Array.from(syncSubdomainsWithVendors(draft));
      let role: DashboardRole;
      if (editingRole) {
        role = await updateRole(editingRole.id, {
          name: editingRole.is_system ? undefined : name,
          permissions,
        });
        role = await setRoleMembers(
          editingRole.id,
          selectedMembers.map((m) => ({ email: m.email, name: m.name })),
        );
      } else {
        role = await createRole({ name, permissions });
        if (selectedMembers.length > 0) {
          role = await setRoleMembers(
            role.id,
            selectedMembers.map((m) => ({ email: m.email, name: m.name })),
          );
        }
      }
      await reload();
      setModalOpen(false);
      setEditingRole(null);
      flashSuccess(editingRole ? `Updated “${role.name}”` : `Created “${role.name}”`);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (role: DashboardRole) => {
    if (!canManageRoles || role.is_system) return;
    if (
      !window.confirm(
        `Delete role "${role.name}"? Assigned users will lose this role's access.`,
      )
    ) {
      return;
    }
    setSaving(true);
    setSaveError('');
    try {
      await deleteRole(role.id);
      await reload();
      if (editingRole?.id === role.id) {
        setModalOpen(false);
        setEditingRole(null);
      }
      flashSuccess(`Deleted “${role.name}”`);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setSaving(false);
    }
  };

  const reassignUser = async (user: AssignedUser, nextRoleId: number) => {
    if (!canManageRoles || nextRoleId === user.roleId) return;
    const target = roles.find((r) => r.id === nextRoleId);
    if (!target) return;
    setAssigningEmail(user.email);
    setSaveError('');
    try {
      const nextMembers = [
        ...target.members
          .filter((m) => m.email.toLowerCase() !== user.email)
          .map((m) => ({ email: m.email.toLowerCase(), name: m.name || m.email })),
        { email: user.email, name: user.name },
      ];
      await setRoleMembers(target.id, nextMembers);
      await reload();
      flashSuccess(`Moved ${user.name} to ${target.name}`);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to reassign user');
    } finally {
      setAssigningEmail(null);
    }
  };

  if (!canAccessPage) {
    return (
      <Layout activeSection="admin">
        <div className="am-page">
          <div className="am-denied">
            <i className="fas fa-lock" />
            <h2>Access Denied</h2>
            <p>
              Access Management requires membership in the admin SSO group and
              the Administration permission.
            </p>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout activeSection="admin">
      <div className="am-page">
        <div className="page-header am-page-head">
          <div>
            <h1>Access Management</h1>
            <p>
              Create roles, set feature access, and assign people across Vendiant.
              {!canManageRoles && ' You have read-only access.'}
            </p>
          </div>
          {canManageRoles && (
            <div className="page-actions">
              <button type="button" className="am-cta" onClick={openCreate}>
                <i className="fas fa-plus" />
                Create Role
              </button>
            </div>
          )}
        </div>

        {successMessage && (
          <div className="am-banner am-banner-success">
            <i className="fas fa-check-circle" />
            <span>{successMessage}</span>
          </div>
        )}
        {(loadError || (saveError && !modalOpen)) && (
          <div className="am-banner am-banner-error">
            <i className="fas fa-exclamation-circle" />
            <span>{loadError || saveError}</span>
          </div>
        )}

        <div className="am-toolbar">
          <div className="am-view-toggle" role="tablist" aria-label="Access views">
            <button
              type="button"
              role="tab"
              aria-selected={view === 'roles'}
              className={view === 'roles' ? 'active' : ''}
              onClick={() => {
                setView('roles');
                setSearch('');
              }}
            >
              <i className="fas fa-user-shield" />
              Roles
              <span className="am-tab-count">{roles.length}</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={view === 'users'}
              className={view === 'users' ? 'active' : ''}
              onClick={() => {
                setView('users');
                setSearch('');
              }}
            >
              <i className="fas fa-users" />
              Users
              <span className="am-tab-count">{assignedUsers.length}</span>
            </button>
          </div>

          <div className="am-search-wrap">
            <i className="fas fa-search" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={
                view === 'roles'
                  ? 'Search roles or members…'
                  : 'Search users or roles…'
              }
            />
          </div>
        </div>

        <div
          className="am-panel"
          style={{
            backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
          }}
        >
          {loadingList ? (
            <div className="am-empty-state">
              <div className="am-spinner" />
              <p>Loading access data…</p>
            </div>
          ) : view === 'roles' ? (
            filteredRoles.length === 0 ? (
              <div className="am-empty-state">
                <i className="fas fa-user-shield" />
                <h3>No roles found</h3>
                <p>Try another search, or create a custom role.</p>
              </div>
            ) : (
              <div className="am-table-scroll">
                <table className="am-data-table">
                  <thead>
                    <tr>
                      <th>Role</th>
                      <th>Type</th>
                      <th>Permissions</th>
                      <th>Members</th>
                      <th>Updated</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRoles.map((role) => (
                      <tr key={role.id}>
                        <td>
                          <div className="am-role-cell">
                            <div className={`am-role-icon tone-${roleTone(role)}`}>
                              <i
                                className={`fas fa-${
                                  role.is_system ? 'shield-alt' : 'puzzle-piece'
                                }`}
                              />
                            </div>
                            <div>
                              <div className="am-primary-text">{role.name}</div>
                              <div className="am-secondary-text">{role.slug}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`am-pill tone-${roleTone(role)}`}>
                            {role.is_system ? 'System' : 'Custom'}
                          </span>
                        </td>
                        <td>
                          <span className="am-metric">
                            {countEnabledFeatures(role.permissions ?? [])}
                            <span>/{TOTAL_FEATURE_ROWS}</span>
                          </span>
                        </td>
                        <td>
                          <div className="am-member-stack">
                            {role.members.slice(0, 3).map((m) => (
                              <span
                                key={m.email}
                                className="am-mini-avatar"
                                title={m.name || m.email}
                                style={{ background: avatarHue(m.email) }}
                              >
                                {initials(m.name || m.email)}
                              </span>
                            ))}
                            {role.member_count > 3 && (
                              <span className="am-more-count">
                                +{role.member_count - 3}
                              </span>
                            )}
                            {role.member_count === 0 && (
                              <span className="am-secondary-text">No members</span>
                            )}
                          </div>
                        </td>
                        <td className="am-secondary-text">{formatDate(role.updated_at)}</td>
                        <td>
                          <div className="am-actions">
                            <button
                              type="button"
                              className="am-icon-action"
                              title={canManageRoles ? 'Edit role' : 'View role'}
                              onClick={() => openEdit(role)}
                            >
                              <i className={`fas fa-${canManageRoles ? 'pen' : 'eye'}`} />
                            </button>
                            {canManageRoles && !role.is_system && (
                              <button
                                type="button"
                                className="am-icon-action danger"
                                title="Delete role"
                                disabled={saving}
                                onClick={() => void handleDelete(role)}
                              >
                                <i className="fas fa-trash" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          ) : filteredUsers.length === 0 ? (
            <div className="am-empty-state">
              <i className="fas fa-users" />
              <h3>No assigned users</h3>
              <p>Assign people from a role to see them here.</p>
            </div>
          ) : (
            <div className="am-table-scroll">
              <table className="am-data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Updated</th>
                    <th>Change role</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((user) => (
                    <tr key={user.email}>
                      <td>
                        <div className="am-role-cell">
                          <span
                            className="am-avatar"
                            style={{ background: avatarHue(user.email) }}
                          >
                            {initials(user.name)}
                          </span>
                          <div>
                            <div className="am-primary-text">{user.name}</div>
                            <div className="am-secondary-text">{user.email}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`am-pill tone-${roleTone({ slug: user.roleSlug, is_system: user.isSystem })}`}>
                          {user.roleName}
                        </span>
                      </td>
                      <td className="am-secondary-text">{formatDate(user.updatedAt)}</td>
                      <td>
                        {canManageRoles ? (
                          <div className="am-inline-select">
                            <select
                              value={user.roleId}
                              disabled={assigningEmail === user.email}
                              onChange={(e) =>
                                void reassignUser(user, Number(e.target.value))
                              }
                            >
                              {roles.map((r) => (
                                <option key={r.id} value={r.id}>
                                  {r.name}
                                </option>
                              ))}
                            </select>
                            <i className="fas fa-chevron-down" />
                          </div>
                        ) : (
                          <span className="am-secondary-text">Read only</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {modalOpen && (
          <div className="am-modal-overlay" onClick={closeModal}>
            <div
              className="am-modal am-modal-wide"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
            >
              <div className="am-modal-header">
                <div>
                  <h2>
                    {editingRole
                      ? canManageRoles
                        ? 'Edit role'
                        : 'View role'
                      : 'Create role'}
                  </h2>
                  <p>
                    {editingRole?.is_system
                      ? 'System role — name is fixed; permissions and members can still be managed.'
                      : 'Set permissions and assign people to this role.'}
                  </p>
                </div>
                <button
                  type="button"
                  className="am-icon-action"
                  onClick={closeModal}
                  aria-label="Close"
                >
                  <i className="fas fa-times" />
                </button>
              </div>

              <div className="am-modal-body">
                <div className="am-field">
                  <label>Role name</label>
                  <input
                    type="text"
                    value={roleName}
                    disabled={!canManageRoles || !!editingRole?.is_system}
                    onChange={(e) => setRoleName(e.target.value)}
                    placeholder="e.g. Security analysts"
                  />
                </div>

                {canManageRoles && !editingRole && (
                  <div className="am-preset-chips">
                    <span>Start from</span>
                    <button type="button" onClick={() => applySystemPreset('admin')}>
                      Admin
                    </button>
                    <button type="button" onClick={() => applySystemPreset('user-extended')}>
                      Extended
                    </button>
                    <button type="button" onClick={() => applySystemPreset('user-basic')}>
                      Viewer
                    </button>
                  </div>
                )}

                <div className="am-section-label">
                  Permissions
                  <span>
                    {countEnabledFeatures(draft)}/{TOTAL_FEATURE_ROWS} enabled
                  </span>
                </div>

                <div className="am-perm-grid">
                  {ACCESS_SECTIONS.map((section) => (
                    <div key={section.title} className="am-perm-card">
                      <div className="am-perm-card-title">{section.title}</div>
                      {section.rows.map((row) => (
                        <div key={row.id} className="am-access-row">
                          <span className="am-access-label">{row.label}</span>
                          <div className="am-access-toggle">
                            {levelsForRow(row).map((opt) => (
                              <button
                                key={opt.value}
                                type="button"
                                className={`am-access-opt${
                                  rowLevels[row.id] === opt.value ? ' active' : ''
                                }`}
                                disabled={!canManageRoles}
                                onClick={() => setAccessLevel(row, opt.value)}
                              >
                                {opt.label}
                              </button>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>

                <div className="am-section-label">
                  Assign users
                  <span>
                    {selectedMembers.length} member
                    {selectedMembers.length === 1 ? '' : 's'}
                  </span>
                </div>

                {selectedMembers.length > 0 && (
                  <div className="am-chip-row">
                    {selectedMembers.map((m) => (
                      <span key={m.email} className="am-chip">
                        <span
                          className="am-mini-avatar"
                          style={{ background: avatarHue(m.email) }}
                        >
                          {initials(m.name)}
                        </span>
                        {m.name}
                        {canManageRoles && (
                          <button type="button" onClick={() => removeMember(m.email)}>
                            <i className="fas fa-times" />
                          </button>
                        )}
                      </span>
                    ))}
                  </div>
                )}

                {canManageRoles && (
                  <div className="am-dropdown" ref={memberDropdownRef}>
                    <button
                      type="button"
                      className="am-dropdown-trigger"
                      onClick={() => setMemberDropdownOpen((o) => !o)}
                    >
                      <span>
                        <i className="fas fa-user-plus" />
                        {selectedMembers.length
                          ? 'Add another person'
                          : 'Select people to assign'}
                      </span>
                      <i
                        className={`fas fa-chevron-${memberDropdownOpen ? 'up' : 'down'}`}
                      />
                    </button>
                    {memberDropdownOpen && (
                      <div className="am-dropdown-panel">
                        <div className="am-dropdown-search">
                          <i className="fas fa-search" />
                          <input
                            autoFocus
                            type="search"
                            placeholder="Search by name or email…"
                            value={memberSearch}
                            onChange={(e) => setMemberSearch(e.target.value)}
                          />
                        </div>
                        <div className="am-dropdown-list">
                          {memberOptions.length === 0 ? (
                            <div className="am-dropdown-empty">No matching people</div>
                          ) : (
                            memberOptions.map((emp) => (
                              <button
                                key={emp.email}
                                type="button"
                                className="am-dropdown-item"
                                onClick={() => addMember(emp)}
                              >
                                <span
                                  className="am-mini-avatar"
                                  style={{ background: avatarHue(emp.email) }}
                                >
                                  {initials(emp.name)}
                                </span>
                                <span>
                                  <strong>{emp.name}</strong>
                                  <em>{emp.email}</em>
                                </span>
                              </button>
                            ))
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="am-modal-footer">
                <span className="am-secondary-text">
                  {countEnabledFeatures(draft)}/{TOTAL_FEATURE_ROWS} enabled ·{' '}
                  {selectedMembers.length} member
                  {selectedMembers.length === 1 ? '' : 's'}
                </span>
                <div className="am-footer-actions">
                  <button type="button" className="am-btn-secondary" onClick={closeModal}>
                    {canManageRoles ? 'Cancel' : 'Close'}
                  </button>
                  {canManageRoles && (
                    <button
                      type="button"
                      className="am-cta"
                      onClick={() => void handleSave()}
                      disabled={saving}
                    >
                      <i className="fas fa-save" />
                      {saving ? 'Saving…' : 'Save role'}
                    </button>
                  )}
                </div>
              </div>
              {saveError && (
                <div className="am-banner am-banner-error am-banner-inline">
                  <i className="fas fa-exclamation-circle" />
                  <span>{saveError}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AdminManagementPage;
