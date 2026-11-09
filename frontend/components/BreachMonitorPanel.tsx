'use client';

import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useUser } from '../lib/user-context';
import { useIsAdmin, useCanViewPasswords, usePermission } from '../lib/rbac';

interface BreachMonitorRecord {
  type: string;
  information: {
    email?: string;
    username?: string;
    domain?: string;
    password?: number;
    /** Plaintext password — only sent by API for the admin role */
    password_plain?: string;
    web_address?: string;
    uid?: string;
    date?: string;
    [key: string]: any;
  };
  source: {
    name: string;
    description: string;
    confidence: string;
    breach_type: string;
    source: string;
    recommendations: string;
    score_attribution?: number;
    score_authentication?: number;
    ingested_date?: string;
    [key: string]: any;
  };
  validated: number;
  /** Present when loaded from API; Slack alerts suppressed per ignore list for this email/source */
  slack_notifications_suppressed?: boolean;
  breach_monitor_uid?: string;
  status?: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
  false_positive_at?: string | null;
  false_positive_by?: string | null;
}

/** Separate Breach Monitor views — client vs employee leaks (by domain) */
export type BreachMonitorLeakView = 'clients' | 'employees';

/** Which date column the From/To range applies to on the server */
export type BreachMonitorDateField = 'ingested' | 'exposure';

interface BreachMonitorPanelProps {
  breaches: BreachMonitorRecord[];
  loading?: boolean;
  leakView: BreachMonitorLeakView;
  /** Refetch remaining API call budget after live Breach Monitor queries */
  onQuotaRefresh?: () => void | Promise<void>;
  /** Reload breach rows from DB after domain sync (e.g. GET /api/breach-monitor) */
  onBreachesReload?: () => void | Promise<void>;
  /** Optional toast after successful domain refresh */
  onDomainRefreshSuccess?: () => void;
  /** Inclusive YYYY-MM-DD filter; column selected by dateField */
  dateFrom?: string;
  dateTo?: string;
  onDateFromChange?: (value: string) => void;
  onDateToChange?: (value: string) => void;
  /** ingested (default) or exposure — which date the range filters on */
  dateField?: BreachMonitorDateField;
  onDateFieldChange?: (value: BreachMonitorDateField) => void;
}

interface DetailModalData {
  breach: BreachMonitorRecord;
  isOpen: boolean;
}

interface QueryModalData {
  isOpen: boolean;
  queryType: 'domain' | 'email' | 'web_address' | null;
  queryValue: string;
  webAddressEmails: string;
  results: BreachMonitorRecord[];
  loading: boolean;
  hasMore: boolean;
  nextId: string;
  hasQueried: boolean;
}

interface IgnoreListEntry {
  id: number;
  email: string;
  incident_names: string[];
  passwords: string[];
  notes: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

type IgnoreListView = 'list' | 'add';

// "all" or one of the employee email domains configured on the backend
// (EMPLOYEE_EMAIL_DOMAINS). Loaded from /api/breach-monitor/config at mount;
// NEXT_PUBLIC_EMPLOYEE_EMAIL_DOMAINS is the build-time fallback.
type BreachMonitorOrgFilter = string;

const FALLBACK_EMPLOYEE_EMAIL_DOMAINS: string[] = (process.env.NEXT_PUBLIC_EMPLOYEE_EMAIL_DOMAINS || '')
  .split(',')
  .map((d) => d.trim().toLowerCase())
  .filter(Boolean);

let EMPLOYEE_EMAIL_DOMAINS: string[] = FALLBACK_EMPLOYEE_EMAIL_DOMAINS;

function setEmployeeEmailDomains(domains: string[]): void {
  EMPLOYEE_EMAIL_DOMAINS = domains.map((d) => d.trim().toLowerCase()).filter(Boolean);
}

const BREACH_MONITOR_QUERY_PAGE_SIZE = 25;

type BreachMonitorQueryPagination = {
  total?: number;
  count?: number;
  page?: number;
};

function paginationInt(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && !Number.isNaN(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    if (!Number.isNaN(n)) return n;
  }
  return fallback;
}

/**
 * Show "Load more" only when there is a next page cursor and the API reports more than
 * one page of results (the breach platform page size is 25). total <= 25 means everything fits on one page.
 */
function breachMonitorQueryHasMorePages(
  nextId: string | null | undefined,
  pagination?: BreachMonitorQueryPagination | null,
): boolean {
  if (nextId == null) return false;
  const trimmed = String(nextId).trim();
  if (!trimmed || trimmed.toLowerCase() === 'null') return false;

  const total = paginationInt(pagination?.total, -1);
  if (total >= 0 && total <= BREACH_MONITOR_QUERY_PAGE_SIZE) return false;

  const count = paginationInt(pagination?.count, -1);
  if (count >= 0 && count < BREACH_MONITOR_QUERY_PAGE_SIZE) return false;

  return true;
}

/** Filter breach list by Slack ignore-list suppression */
type SlackIgnoreFilter = 'all' | 'hide_ignored' | 'ignored_only';

/** Botnet (infostealer) vs traditional breach / other Breach Monitor result types */
type BreachMonitorIntelTypeFilter = 'all' | 'botnet' | 'other';

/** Filter by whether a password was exposed in the breach record */
type PasswordExposureFilter = 'all' | 'with_password' | 'without_password';

type ResolveStatusFilter = 'all' | 'active' | 'resolved' | 'false_positive';

/** True when the record is classified as botnet / infostealer intel (Breach Monitor API shape). */
function breachIsBotnet(breach: BreachMonitorRecord): boolean {
  const breachType = String(breach.source?.breach_type ?? '').toLowerCase();
  if (breachType === 'botnet') return true;
  const sourceType = String((breach.source as { type?: string })?.type ?? '').toLowerCase();
  if (sourceType === 'botnet') return true;
  const recordType = String(breach.type ?? '').toLowerCase();
  if (recordType.includes('botnet')) return true;
  return false;
}

function breachMatchesIntelTypeFilter(
  breach: BreachMonitorRecord,
  filter: BreachMonitorIntelTypeFilter,
): boolean {
  if (filter === 'all') return true;
  const isBotnet = breachIsBotnet(breach);
  if (filter === 'botnet') return isBotnet;
  return !isBotnet;
}

function breachIsEmployeeRecord(breach: BreachMonitorRecord): boolean {
  const domain = (breach.information.domain || '').toLowerCase().trim();
  if (!domain) return false;
  return EMPLOYEE_EMAIL_DOMAINS.some(
    (employeeDomain) =>
      domain === employeeDomain || domain.endsWith(`.${employeeDomain}`),
  );
}

function breachMatchesLeakView(breach: BreachMonitorRecord, view: BreachMonitorLeakView): boolean {
  const isEmployee = breachIsEmployeeRecord(breach);
  return view === 'employees' ? isEmployee : !isEmployee;
}

function breachMatchesOrgFilter(breach: BreachMonitorRecord, filter: BreachMonitorOrgFilter): boolean {
  if (filter === 'all') return true;
  const email = (breach.information.email || '').toLowerCase();
  const domain = (breach.information.domain || '').toLowerCase();
  const username = String(breach.information.username || '').toLowerCase();
  const org = filter.trim().toLowerCase();
  if (EMPLOYEE_EMAIL_DOMAINS.includes(org)) {
    return (
      domain === org ||
      domain.endsWith(`.${org}`) ||
      email.endsWith(`@${org}`) ||
      username.endsWith(`@${org}`)
    );
  }
  return true;
}

function getConfidenceBadgeClass(confidence: string): string {
  const c = (confidence || '').toLowerCase();
  if (c === 'high') return 'badge-confidence-high';
  if (c === 'medium' || c === 'med') return 'badge-confidence-medium';
  if (c === 'low') return 'badge-confidence-low';
  return 'badge-confidence-default';
}

function formatDate(dateStr?: string): string {
  if (!dateStr) return 'Unknown';
  const d = dateStr.split('T')[0];
  return d || 'Unknown';
}

/** Parse Breach Monitor ingestion timestamp for stable newest-first ordering. */
function ingestionTimeMs(breach: BreachMonitorRecord): number {
  const raw = (breach.source?.ingested_date || '').trim();
  if (!raw) return 0;
  const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T');
  const t = Date.parse(normalized);
  return Number.isNaN(t) ? 0 : t;
}

function sortBreachesByIngestionDesc(breaches: BreachMonitorRecord[]): BreachMonitorRecord[] {
  return [...breaches].sort((a, b) => ingestionTimeMs(b) - ingestionTimeMs(a));
}

/** Mask plaintext for display until admin explicitly reveals it. */
function maskPlainPassword(plain: string): string {
  const n = Math.min(Math.max(plain.length, 10), 48);
  return '\u2022'.repeat(n);
}

/** True when the breach record indicates a password was exposed (API flag or plaintext present). */
function breachIndicatesPasswordExposure(breach: BreachMonitorRecord): boolean {
  const p = breach.information?.password;
  if (p !== undefined && p !== null && Number(p) !== 0) return true;
  if (breach.information?.password_plain) return true;
  return false;
}

export const BreachMonitorPanel: React.FC<BreachMonitorPanelProps> = ({
  breaches = [],
  loading = false,
  onQuotaRefresh,
  onBreachesReload,
  onDomainRefreshSuccess,
  leakView,
  dateFrom = '',
  dateTo = '',
  onDateFromChange,
  dateField = 'ingested',
  onDateFieldChange,
  onDateToChange,
}) => {
  const { email, name, role, sub } = useUser();
  const isAdmin = useIsAdmin();
  const canViewPasswords = useCanViewPasswords();
  const canQueryInternalBreaches = usePermission('query_internal_breaches');
  const [domainRefreshing, setDomainRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [orgFilter, setOrgFilter] = useState<BreachMonitorOrgFilter>('all');
  const [employeeDomains, setEmployeeDomains] = useState<string[]>(FALLBACK_EMPLOYEE_EMAIL_DOMAINS);

  // Employee email domains drive the "employees vs clients" split and the
  // organisation filter; they are configured on the backend.
  useEffect(() => {
    let cancelled = false;
    fetch('/api/breach-monitor/config', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg) => {
        const doms = Array.isArray(cfg?.employee_email_domains) ? cfg.employee_email_domains : null;
        if (!cancelled && doms) {
          setEmployeeEmailDomains(doms);
          setEmployeeDomains(doms.map((d: string) => d.toLowerCase()));
        }
      })
      .catch(() => {
        /* keep fallback */
      });
    return () => {
      cancelled = true;
    };
  }, []);
  const [slackIgnoreFilter, setSlackIgnoreFilter] = useState<SlackIgnoreFilter>('all');
  const [intelTypeFilter, setIntelTypeFilter] = useState<BreachMonitorIntelTypeFilter>('all');
  const [passwordFilter, setPasswordFilter] = useState<PasswordExposureFilter>('all');
  const [resolveStatusFilter, setResolveStatusFilter] = useState<ResolveStatusFilter>('all');
  const [filterDrawerOpen, setFilterDrawerOpen] = useState(false);
  // Drawer is portalled to <body>; only render it after mount so SSR output matches.
  const [drawerMounted, setDrawerMounted] = useState(false);
  useEffect(() => setDrawerMounted(true), []);
  const [exporting, setExporting] = useState(false);
  const [resolveLoadingUids, setResolveLoadingUids] = useState<Set<string>>(new Set());
  const [bulkResolveLoading, setBulkResolveLoading] = useState(false);
  const [fpLoadingUids, setFpLoadingUids] = useState<Set<string>>(new Set());
  const [bulkFpLoading, setBulkFpLoading] = useState(false);
  const [detailModal, setDetailModal] = useState<DetailModalData>({ breach: null as any, isOpen: false });
  const [queryModal, setQueryModal] = useState<QueryModalData>({
    isOpen: false,
    queryType: null,
    queryValue: '',
    webAddressEmails: '',
    results: [],
    loading: false,
    hasMore: false,
    nextId: '',
    hasQueried: false,
  });
  const [expandedBreachIndex, setExpandedBreachIndex] = useState<number | null>(null);

  /** Admin-only: detail modal plaintext starts hidden until eye icon is used */
  const [detailPasswordRevealed, setDetailPasswordRevealed] = useState(false);
  /** Admin-only: query-result rows keyed by information.uid (reveal password plaintext) */
  const [queryPasswordRevealedUids, setQueryPasswordRevealedUids] = useState<Set<string>>(
    () => new Set(),
  );

  // ── Row selection state ──
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());

  // ── Ignore List modal state ──
  const [ignoreListOpen, setIgnoreListOpen] = useState(false);
  const [ignoreListView, setIgnoreListView] = useState<IgnoreListView>('list');
  const [ignoreListEntries, setIgnoreListEntries] = useState<IgnoreListEntry[]>([]);
  const [ignoreListLoading, setIgnoreListLoading] = useState(false);
  const [ignoreListError, setIgnoreListError] = useState<string | null>(null);
  const [allIncidents, setAllIncidents] = useState<string[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [addEmails, setAddEmails] = useState<string[]>([]);
  const [addEmailInput, setAddEmailInput] = useState('');
  const [addNotes, setAddNotes] = useState('');
  const [addSelectedIncidents, setAddSelectedIncidents] = useState<string[]>([]);
  const [availablePasswordsByEmail, setAvailablePasswordsByEmail] = useState<Record<string, string[]>>({});
  const [addSelectedPasswords, setAddSelectedPasswords] = useState<string[]>([]);
  const [passwordsLoading, setPasswordsLoading] = useState(false);
  const [addSubmitting, setAddSubmitting] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [addSuccess, setAddSuccess] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);
  const incidentSearchRef = useRef<HTMLInputElement>(null);
  const [incidentSearchTerm, setIncidentSearchTerm] = useState('');

  useEffect(() => {
    setOrgFilter('all');
    setSelectedRows(new Set());
  }, [leakView]);

  const viewBreaches = useMemo(
    () => breaches.filter((b) => breachMatchesLeakView(b, leakView)),
    [breaches, leakView],
  );

  const orgFilteredBreaches = useMemo(() => {
    return orgFilter === 'all'
      ? viewBreaches
      : viewBreaches.filter((b) => breachMatchesOrgFilter(b, orgFilter));
  }, [viewBreaches, orgFilter]);

  const slackIgnoredCount = useMemo(
    () => orgFilteredBreaches.filter((b) => b.slack_notifications_suppressed).length,
    [orgFilteredBreaches]
  );

  const slackFilteredBreaches = useMemo(() => {
    let list = orgFilteredBreaches;
    if (slackIgnoreFilter === 'hide_ignored') {
      list = list.filter((b) => !b.slack_notifications_suppressed);
    } else if (slackIgnoreFilter === 'ignored_only') {
      list = list.filter((b) => !!b.slack_notifications_suppressed);
    }
    return list;
  }, [orgFilteredBreaches, slackIgnoreFilter]);

  const typeFilteredBreaches = useMemo(
    () => slackFilteredBreaches.filter((b) => breachMatchesIntelTypeFilter(b, intelTypeFilter)),
    [slackFilteredBreaches, intelTypeFilter],
  );

  const passwordFilteredBreaches = useMemo(() => {
    if (passwordFilter === 'all') return typeFilteredBreaches;
    return typeFilteredBreaches.filter((b) => {
      const hasPassword = breachIndicatesPasswordExposure(b);
      return passwordFilter === 'with_password' ? hasPassword : !hasPassword;
    });
  }, [typeFilteredBreaches, passwordFilter]);

  const resolveFilteredBreaches = useMemo(() => {
    if (resolveStatusFilter === 'all') return passwordFilteredBreaches;
    if (resolveStatusFilter === 'false_positive') return passwordFilteredBreaches.filter((b) => b.status === 'false_positive');
    return passwordFilteredBreaches.filter((b) =>
      resolveStatusFilter === 'resolved' ? b.status === 'resolved' : (b.status || 'active') === 'active',
    );
  }, [passwordFilteredBreaches, resolveStatusFilter]);

  const filteredBreaches = useMemo(() => {
    const base = !searchTerm
      ? resolveFilteredBreaches
      : (() => {
          const term = searchTerm.toLowerCase();
          return resolveFilteredBreaches.filter(
            (breach) =>
              (breach.information.email?.toLowerCase().includes(term) || false) ||
              (breach.information.username?.toLowerCase().includes(term) || false) ||
              (breach.information.web_address?.toLowerCase().includes(term) || false) ||
              (breach.source.name?.toLowerCase().includes(term) || false) ||
              (breach.source.description?.toLowerCase().includes(term) || false),
          );
        })();
    return sortBreachesByIngestionDesc(base);
  }, [resolveFilteredBreaches, searchTerm]);

  const hasActiveFilters =
    searchTerm ||
    orgFilter !== 'all' ||
    dateFrom ||
    dateTo ||
    slackIgnoreFilter !== 'all' ||
    intelTypeFilter !== 'all' ||
    passwordFilter !== 'all' ||
    resolveStatusFilter !== 'all';

  const activeFilterCount =
    (orgFilter !== 'all' ? 1 : 0) +
    (slackIgnoreFilter !== 'all' ? 1 : 0) +
    (intelTypeFilter !== 'all' ? 1 : 0) +
    (passwordFilter !== 'all' ? 1 : 0) +
    (resolveStatusFilter !== 'all' ? 1 : 0) +
    (dateFrom ? 1 : 0) +
    (dateTo ? 1 : 0);

  // Clear row selection whenever the filtered set changes
  useEffect(() => {
    setSelectedRows(new Set());
  }, [filteredBreaches]);

  const clearAllFilters = () => {
    setSearchTerm('');
    setOrgFilter('all');
    setSlackIgnoreFilter('all');
    setIntelTypeFilter('all');
    setPasswordFilter('all');
    setResolveStatusFilter('all');
    onDateFromChange?.('');
    onDateToChange?.('');
    onDateFieldChange?.('ingested');
  };

  const handleExportExcel = useCallback(async () => {
    if (exporting || loading) return;
    const selectedUids =
      selectedRows.size > 0
        ? Array.from(selectedRows)
            .map((index) => filteredBreaches[index]?.breach_monitor_uid)
            .filter((uid): uid is string => Boolean(uid))
        : [];
    if (selectedRows.size > 0 && selectedUids.length === 0) {
      alert('Selected rows are missing leak identifiers and cannot be exported.');
      return;
    }
    // Selecting every filtered row is equivalent to a filter-only export — skip the
    // UID list so large "select all" exports stay fast as the dataset grows.
    const exportAllFiltered =
      selectedRows.size > 0 && selectedRows.size === filteredBreaches.length;
    const uidsForExport = exportAllFiltered ? [] : selectedUids;

    setExporting(true);
    try {
      // POST body avoids HTTP 414 when many selected UIDs would overflow the query string.
      // Backend loads selected UIDs from the DB in batches and streams large Excel files.
      const body: Record<string, unknown> = {
        leak_view: leakView,
        org_filter: orgFilter,
        slack_ignore_filter: slackIgnoreFilter,
        intel_type_filter: intelTypeFilter,
        password_filter: passwordFilter,
        resolve_status_filter: resolveStatusFilter,
        date_field: dateField,
      };
      if (searchTerm.trim()) body.search = searchTerm.trim();
      if (dateFrom.trim()) body.date_from = dateFrom.trim();
      if (dateTo.trim()) body.date_to = dateTo.trim();
      if (uidsForExport.length > 0) body.uids = uidsForExport;

      const response = await fetch('/api/breach-monitor/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        let message = 'Failed to export credential leaks';
        try {
          const err = await response.json();
          if (typeof err.detail === 'string') {
            message = err.detail;
          } else if (typeof err.message === 'string' && err.message !== 'Validation error') {
            message = err.message;
          } else if (Array.isArray(err.details) && err.details[0]?.msg) {
            message = String(err.details[0].msg);
          } else if (typeof err.error === 'string') {
            message = err.error;
          } else if (err.message) {
            message = String(err.message);
          }
        } catch {
          // ignore parse errors
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const disposition = response.headers.get('content-disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      const filename =
        filenameMatch?.[1] ||
        `breach-monitor-${leakView}-credential-leaks.xlsx`;

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      anchor.rel = 'noopener';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Breach Monitor export failed:', error);
      alert(error instanceof Error ? error.message : 'Failed to export credential leaks');
    } finally {
      setExporting(false);
    }
  }, [
    exporting,
    loading,
    selectedRows,
    filteredBreaches,
    leakView,
    orgFilter,
    slackIgnoreFilter,
    intelTypeFilter,
    passwordFilter,
    resolveStatusFilter,
    searchTerm,
    dateFrom,
    dateTo,
    dateField,
  ]);

  const openDetailModal = (breach: BreachMonitorRecord) => {
    setDetailPasswordRevealed(false);
    setDetailModal({ breach, isOpen: true });
  };

  const closeDetailModal = () => {
    setDetailPasswordRevealed(false);
    setDetailModal({ breach: null as any, isOpen: false });
  };

  const openQueryModal = (queryType?: 'domain' | 'email' | 'web_address') => {
    setQueryModal(prev => ({
      ...prev,
      isOpen: true,
      queryType: queryType || null,
      queryValue: '',
      webAddressEmails: '',
      results: [],
      loading: false,
      hasMore: false,
      nextId: '',
      hasQueried: false,
    }));
  };

  const closeQueryModal = () => {
    setQueryPasswordRevealedUids(new Set());
    setQueryModal(prev => ({
      ...prev,
      isOpen: false,
      queryType: null,
      queryValue: '',
      webAddressEmails: '',
      results: [],
      loading: false,
      hasMore: false,
      nextId: '',
      hasQueried: false,
    }));
  };

  const toggleQueryPasswordReveal = useCallback((uid: string) => {
    if (!uid) return;
    setQueryPasswordRevealedUids((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  }, []);

  const executeQuery = async (nextId: string = '') => {
    if (!isAdmin || !role) {
      return;
    }
    if (!queryModal.queryValue.trim()) {
      alert('Please enter a value');
      return;
    }

    setQueryModal(prev => ({
      ...prev,
      loading: true,
      ...(nextId
        ? {}
        : {
            hasMore: false,
            nextId: '',
          }),
    }));

    try {
      const body: Record<string, string | undefined> =
        queryModal.queryType === 'domain'
          ? {
            type: 'domain',
            domain: queryModal.queryValue.trim(),
            next_id: nextId || undefined,
          }
          : queryModal.queryType === 'web_address'
          ? {
            type: 'web_address',
            web_address: queryModal.queryValue.trim(),
            emails: queryModal.webAddressEmails.trim() || undefined,
            next_id: nextId || undefined,
          }
          : {
            type: 'email',
            email: queryModal.queryValue.trim(),
            next_id: nextId || undefined,
          };

      const res = await fetch('/api/breach-monitor/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = (data as { detail?: string | string[] }).detail;
        const msg = Array.isArray(detail) ? detail.join(', ') : detail || res.statusText;
        throw new Error(msg || 'Query failed');
      }

      if (data && data.data && data.data.results) {
        const payload = data.data as {
          next_id?: string | null;
          query?: { pagination?: BreachMonitorQueryPagination };
        };
        const rawNextId = payload.next_id;
        const pagination = payload.query?.pagination;
        const hasMore = breachMonitorQueryHasMorePages(rawNextId, pagination);
        const cursor = hasMore ? String(rawNextId).trim() : '';
        setQueryModal(prev => ({
          ...prev,
          results: nextId ? [...prev.results, ...data.data.results] : data.data.results,
          hasMore,
          nextId: cursor,
          loading: false,
          hasQueried: true,
        }));
        await Promise.resolve(onQuotaRefresh?.());
      } else {
        throw new Error('Invalid response format');
      }
    } catch (error) {
      console.error('Query error:', error);
      alert('Error executing query: ' + (error instanceof Error ? error.message : 'Unknown error'));
      setQueryModal(prev => ({ ...prev, loading: false, hasQueried: true }));
    }
  };

  const handleDomainRefresh = useCallback(async () => {
    if (!role || domainRefreshing) return;
    setDomainRefreshing(true);
    try {
      const res = await fetch('/api/breach-monitor/refresh', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = (payload as { detail?: string | string[] }).detail;
        const msg = Array.isArray(detail) ? detail.join(', ') : detail || res.statusText;
        throw new Error(msg || 'Domain refresh failed');
      }
      await Promise.resolve(onBreachesReload?.());
      onDomainRefreshSuccess?.();
    } catch (err) {
      console.error('Breach Monitor domain refresh:', err);
      alert(err instanceof Error ? err.message : 'Domain refresh failed');
    } finally {
      setDomainRefreshing(false);
    }
  }, [role, domainRefreshing, onBreachesReload, onDomainRefreshSuccess]);

  const breachMonitorJsonFetchHeaders = useMemo(
    () => ({ 'Content-Type': 'application/json' }) as const,
    []
  );

  const fetchIgnoreList = useCallback(async () => {
    setIgnoreListLoading(true);
    setIgnoreListError(null);
    try {
      const res = await fetch('/api/breach-monitor/ignore-list', { headers: breachMonitorJsonFetchHeaders });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error((data as { detail?: string }).detail || 'Failed to load ignore list');
      setIgnoreListEntries((data as { data?: IgnoreListEntry[] }).data || []);
    } catch (err) {
      setIgnoreListError(err instanceof Error ? err.message : 'Failed to load ignore list');
    } finally {
      setIgnoreListLoading(false);
    }
  }, [breachMonitorJsonFetchHeaders]);

  const fetchIncidents = useCallback(async () => {
    setIncidentsLoading(true);
    try {
      const res = await fetch('/api/breach-monitor/incidents', { headers: breachMonitorJsonFetchHeaders });
      const data = await res.json().catch(() => ({}));
      if (res.ok) setAllIncidents((data as { incidents?: string[] }).incidents || []);
    } catch {
      // non-fatal — user can still add with empty domain list
    } finally {
      setIncidentsLoading(false);
    }
  }, [breachMonitorJsonFetchHeaders]);

  const openIgnoreList = useCallback(() => {
    setIgnoreListOpen(true);
    setIgnoreListView('list');
    setAddEmails([]);
    setAddEmailInput('');
    setAddNotes('');
    setAddSelectedIncidents([]);
    setAvailablePasswordsByEmail({});
    setAddSelectedPasswords([]);
    setPasswordsLoading(false);
    setAddError(null);
    setAddSuccess(false);
    setIncidentSearchTerm('');
    fetchIgnoreList();
  }, [fetchIgnoreList]);

  const openAddView = useCallback((initialEmails: string[] = []) => {
    setIgnoreListView('add');
    setAddEmails(initialEmails);
    setAddEmailInput('');
    setAddNotes('');
    setAddSelectedIncidents([]);
    setAvailablePasswordsByEmail({});
    setAddSelectedPasswords([]);
    setPasswordsLoading(false);
    setAddError(null);
    setAddSuccess(false);
    setIncidentSearchTerm('');
    if (allIncidents.length === 0) fetchIncidents();
  }, [allIncidents.length, fetchIncidents]);

  // Fetch passwords from breach records whenever the email list changes (add view only)
  useEffect(() => {
    if (!ignoreListOpen || ignoreListView !== 'add' || addEmails.length === 0) return;
    let cancelled = false;
    setPasswordsLoading(true);
    const toFetch = addEmails.filter(e => !(e in availablePasswordsByEmail));
    if (toFetch.length === 0) {
      setPasswordsLoading(false);
      return;
    }
    Promise.all(
      toFetch.map(email =>
        fetch(`/api/breach-monitor/breach-passwords?email=${encodeURIComponent(email)}`, {
          headers: breachMonitorJsonFetchHeaders,
        })
          .then(r => r.json().catch(() => ({})))
          .then(data => ({ email, passwords: (data as { passwords?: string[] }).passwords || [] }))
          .catch(() => ({ email, passwords: [] as string[] }))
      )
    ).then(results => {
      if (cancelled) return;
      setAvailablePasswordsByEmail(prev => {
        const next = { ...prev };
        for (const { email, passwords } of results) next[email] = passwords;
        return next;
      });
      setPasswordsLoading(false);
    });
    return () => { cancelled = true; };
  }, [addEmails, ignoreListOpen, ignoreListView]); // eslint-disable-line react-hooks/exhaustive-deps

  const closeIgnoreList = () => {
    setIgnoreListOpen(false);
    setDeleteConfirmId(null);
  };

  const toggleIncident = (name: string) => {
    setAddSelectedIncidents(prev =>
      prev.includes(name) ? prev.filter(n => n !== name) : [...prev, name]
    );
  };

  const emailRe = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

  const commitEmailInput = useCallback(() => {
    const val = addEmailInput.trim().toLowerCase();
    if (!val) return;
    if (!emailRe.test(val)) {
      setAddError(`"${val}" is not a valid email address.`);
      return;
    }
    if (addEmails.includes(val)) {
      setAddEmailInput('');
      return;
    }
    setAddEmails(prev => [...prev, val]);
    setAddEmailInput('');
    setAddError(null);
  }, [addEmailInput, addEmails, emailRe]);

  const removeEmail = (email: string) => {
    setAddEmails(prev => prev.filter(e => e !== email));
  };

  const handleEmailKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
      e.preventDefault();
      commitEmailInput();
    } else if (e.key === 'Backspace' && !addEmailInput && addEmails.length > 0) {
      setAddEmails(prev => prev.slice(0, -1));
    }
  };

  const handleAddSubmit = async () => {
    // Commit any partially typed email first
    const pending = addEmailInput.trim().toLowerCase();
    const allEmails = [...addEmails];
    if (pending) {
      if (!emailRe.test(pending)) {
        setAddError(`"${pending}" is not a valid email address.`);
        return;
      }
      if (!allEmails.includes(pending)) allEmails.push(pending);
    }
    if (allEmails.length === 0) {
      setAddError('Please enter at least one email address.');
      return;
    }
    setAddSubmitting(true);
    setAddError(null);
    try {
      const results = await Promise.all(
        allEmails.map(email =>
          fetch('/api/breach-monitor/ignore-list', {
            method: 'POST',
            headers: breachMonitorJsonFetchHeaders,
            body: JSON.stringify({
              email,
              incident_names: addSelectedIncidents,
              passwords: addSelectedPasswords,
              notes: addNotes.trim() || null,
            }),
          }).then(async res => {
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error((data as { detail?: string }).detail || `Failed to save ${email}`);
            return data;
          })
        )
      );
      if (results.length > 0) {
        setAddSuccess(true);
        setAddEmailInput('');
        await fetchIgnoreList();
        await onBreachesReload?.();
        setTimeout(() => {
          setIgnoreListView('list');
          setAddSuccess(false);
        }, 1200);
      }
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to save entries');
    } finally {
      setAddSubmitting(false);
    }
  };

  const handleDeleteEntry = async (id: number) => {
    if (deleteConfirmId !== id) {
      setDeleteConfirmId(id);
      return;
    }
    try {
      const res = await fetch(`/api/breach-monitor/ignore-list/${id}`, {
        method: 'DELETE',
        headers: breachMonitorJsonFetchHeaders,
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || 'Delete failed');
      }
      setDeleteConfirmId(null);
      setIgnoreListEntries(prev => prev.filter(e => e.id !== id));
      await onBreachesReload?.();
    } catch (err) {
      setIgnoreListError(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  const filteredIncidents = useMemo(() => {
    if (!incidentSearchTerm) return allIncidents;
    const t = incidentSearchTerm.toLowerCase();
    return allIncidents.filter(n => n.toLowerCase().includes(t));
  }, [allIncidents, incidentSearchTerm]);

  // ── Row selection helpers ──
  const toggleRowSelection = useCallback((index: number, e: React.MouseEvent | React.ChangeEvent) => {
    e.stopPropagation();
    setSelectedRows(prev => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    setSelectedRows(prev => {
      if (prev.size === filteredBreaches.length) return new Set();
      return new Set(filteredBreaches.map((_, i) => i));
    });
  }, [filteredBreaches]);

  const handleToggleResolve = useCallback(async (breach: BreachMonitorRecord, e: React.MouseEvent) => {
    e.stopPropagation();
    const uid = breach.breach_monitor_uid;
    if (!uid || !isAdmin) return;
    const isResolved = breach.status === 'resolved';
    const action = isResolved ? 'unresolve' : 'resolve';
    setResolveLoadingUids(prev => new Set(prev).add(uid));
    try {
      const res = await fetch(`/api/breach-monitor/breaches/${encodeURIComponent(uid)}/${action}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || `Failed to ${action}`);
      }
      await onBreachesReload?.();
    } catch (err) {
      alert(err instanceof Error ? err.message : `Failed to ${action} breach`);
    } finally {
      setResolveLoadingUids(prev => {
        const next = new Set(prev);
        next.delete(uid);
        return next;
      });
    }
  }, [isAdmin, onBreachesReload]);

  const handleBulkResolveAction = useCallback(async (action: 'resolve' | 'unresolve') => {
    if (!isAdmin || selectedRows.size === 0) return;
    const uids = Array.from(selectedRows)
      .map(i => filteredBreaches[i]?.breach_monitor_uid)
      .filter((uid): uid is string => Boolean(uid));
    if (uids.length === 0) return;
    setBulkResolveLoading(true);
    try {
      let res: Response;
      if (uids.length === 1) {
        res = await fetch(`/api/breach-monitor/breaches/${encodeURIComponent(uids[0])}/${action}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
        });
      } else {
        const endpoint = action === 'resolve' ? '/api/breach-monitor/breaches/bulk-resolve' : '/api/breach-monitor/breaches/bulk-unresolve';
        res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ breach_monitor_uids: uids }),
        });
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || `Bulk ${action} failed`);
      }
      setSelectedRows(new Set());
      await onBreachesReload?.();
    } catch (err) {
      alert(err instanceof Error ? err.message : `Bulk ${action} failed`);
    } finally {
      setBulkResolveLoading(false);
    }
  }, [isAdmin, selectedRows, filteredBreaches, onBreachesReload]);

  const handleToggleFalsePositive = useCallback(async (breach: BreachMonitorRecord, e: React.MouseEvent) => {
    e.stopPropagation();
    const uid = breach.breach_monitor_uid;
    if (!uid || !isAdmin) return;
    const isFalsePositive = breach.status === 'false_positive';
    const action = isFalsePositive ? 'unmark-false-positive' : 'mark-false-positive';
    setFpLoadingUids(prev => new Set(prev).add(uid));
    try {
      const res = await fetch(`/api/breach-monitor/breaches/${encodeURIComponent(uid)}/${action}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || `Failed to ${isFalsePositive ? 'unmark' : 'mark'} false positive`);
      }
      await onBreachesReload?.();
    } catch (err) {
      alert(err instanceof Error ? err.message : `Failed to update false positive status`);
    } finally {
      setFpLoadingUids(prev => {
        const next = new Set(prev);
        next.delete(uid);
        return next;
      });
    }
  }, [isAdmin, onBreachesReload]);

  const handleBulkFalsePositiveAction = useCallback(async (action: 'mark' | 'unmark') => {
    if (!isAdmin || selectedRows.size === 0) return;
    const uids = Array.from(selectedRows)
      .map(i => filteredBreaches[i]?.breach_monitor_uid)
      .filter((uid): uid is string => Boolean(uid));
    if (uids.length === 0) return;
    setBulkFpLoading(true);
    try {
      let res: Response;
      if (uids.length === 1) {
        const endpoint = action === 'mark' ? 'mark-false-positive' : 'unmark-false-positive';
        res = await fetch(`/api/breach-monitor/breaches/${encodeURIComponent(uids[0])}/${endpoint}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
        });
      } else {
        const endpoint = action === 'mark'
          ? '/api/breach-monitor/breaches/bulk-mark-false-positive'
          : '/api/breach-monitor/breaches/bulk-unmark-false-positive';
        res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ breach_monitor_uids: uids }),
        });
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || `Bulk ${action} false positive failed`);
      }
      setSelectedRows(new Set());
      await onBreachesReload?.();
    } catch (err) {
      alert(err instanceof Error ? err.message : `Bulk false positive action failed`);
    } finally {
      setBulkFpLoading(false);
    }
  }, [isAdmin, selectedRows, filteredBreaches, onBreachesReload]);

  const handleBulkIgnore = useCallback(() => {
    const emails = Array.from(selectedRows)
      .map(i => filteredBreaches[i]?.information.email)
      .filter((e): e is string => Boolean(e));
    const uniqueEmails = Array.from(new Set(emails));
    if (uniqueEmails.length === 0) return;
    // Open the ignore list modal directly in add view with pre-populated emails
    setIgnoreListOpen(true);
    setIgnoreListView('add');
    setAddEmails(uniqueEmails);
    setAddEmailInput('');
    setAddNotes('');
    setAddSelectedIncidents([]);
    setAvailablePasswordsByEmail({});
    setAddSelectedPasswords([]);
    setPasswordsLoading(false);
    setAddError(null);
    setAddSuccess(false);
    setIncidentSearchTerm('');
    setDeleteConfirmId(null);
    fetchIgnoreList();
    if (allIncidents.length === 0) fetchIncidents();
  }, [selectedRows, filteredBreaches, fetchIgnoreList, fetchIncidents, allIncidents.length]);

  return (
    <>
      <div className="cb-container">
        {/* ── Summary Stats ── */}
        {viewBreaches.length > 0 && (
          <div className="widget-card cb-summary-widget">
            <div className="widget-header">
              <h3 className="cb-section-title">
                <i className="fas fa-chart-bar cb-icon-coral" aria-hidden />
                Summary
                {(orgFilter !== 'all' || slackIgnoreFilter !== 'all' || intelTypeFilter !== 'all' || passwordFilter !== 'all') && (
                  <span className="cb-filter-tag">filtered</span>
                )}
              </h3>
            </div>
            <div className="widget-content">
              <div className="cb-stats-grid">
                <div className="cb-stat-card cb-stat-card--total">
                  <div className="cb-stat-icon">
                    <i className="fas fa-shield-alt"></i>
                  </div>
                  <div className="cb-stat-body">
                    <span className="cb-stat-value">{filteredBreaches.length}</span>
                    <span className="cb-stat-label">Total Breaches</span>
                  </div>
                </div>
                <div className="cb-stat-card cb-stat-card--emails">
                  <div className="cb-stat-icon">
                    <i className="fas fa-envelope"></i>
                  </div>
                  <div className="cb-stat-body">
                    <span className="cb-stat-value">
                      {new Set(filteredBreaches.map((b) => b.information.email)).size}
                    </span>
                    <span className="cb-stat-label">Unique Emails</span>
                  </div>
                </div>
                <div className="cb-stat-card cb-stat-card--sources">
                  <div className="cb-stat-icon">
                    <i className="fas fa-database"></i>
                  </div>
                  <div className="cb-stat-body">
                    <span className="cb-stat-value">
                      {new Set(filteredBreaches.map((b) => b.source.name)).size}
                    </span>
                    <span className="cb-stat-label">Breach Sources</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Breach Records ── */}
        <div className="widget-card cb-records-widget">
          {/* Header row: title + admin actions */}
          <div className="widget-header cb-records-header">
            <h3 className="cb-section-title">
              <i className="fas fa-list cb-icon-coral" aria-hidden />
              {leakView === 'clients' ? 'Client Breach Records' : 'Employee Breach Records'}
              <span className="cb-count-badge">
                {loading ? '—' : filteredBreaches.length}
              </span>
              {slackIgnoredCount > 0 && (
                <span
                  className="cb-ignored-indicator"
                  title="Number of records in this view (after organization filter) with Slack alerts suppressed by the ignore list"
                >
                  <i className="fas fa-bell-slash" aria-hidden />
                  <span className="cb-ignored-indicator__label">{slackIgnoredCount}</span>
                  ignored
                </span>
              )}
            </h3>
            <div className="cb-header-actions">
              {canQueryInternalBreaches && (
                <button
                  type="button"
                  className="btn btn-sm btn-secondary cb-action-btn"
                  onClick={() => openQueryModal()}
                  title="Query by domain, email, or web address"
                  disabled={domainRefreshing}
                >
                  <i className="fas fa-search"></i>
                  Query
                </button>
              )}
              {isAdmin && (
                <>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary cb-action-btn"
                    onClick={handleDomainRefresh}
                    disabled={domainRefreshing || loading}
                    title="Sync breach data from Breach Monitor for configured domains (uses API quota)"
                  >
                    {domainRefreshing ? (
                      <>
                        <i className="fas fa-spinner fa-spin"></i>
                        Syncing…
                      </>
                    ) : (
                      <>
                        <i className="fas fa-sync-alt"></i>
                        Sync
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary cb-action-btn cb-ignore-btn"
                    onClick={openIgnoreList}
                    title="Manage Slack notification ignore list"
                  >
                    <i className="fas fa-bell-slash"></i>
                    Ignore List
                  </button>
                </>
              )}
              <button
                type="button"
                className="btn btn-sm btn-secondary cb-action-btn cb-export-btn"
                onClick={handleExportExcel}
                disabled={
                  exporting ||
                  loading ||
                  (selectedRows.size === 0 && filteredBreaches.length === 0)
                }
                title={
                  selectedRows.size > 0
                    ? `Export ${selectedRows.size} selected leak${selectedRows.size !== 1 ? 's' : ''} to Excel`
                    : filteredBreaches.length === 0
                      ? 'No records to export in the current view'
                      : 'Export filtered credential leaks to Excel'
                }
              >
                {exporting ? (
                  <>
                    <i className="fas fa-spinner fa-spin" aria-hidden />
                    Exporting…
                  </>
                ) : (
                  <>
                    <i className="fas fa-file-excel" aria-hidden />
                    Excel
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Filter bar */}
          <div className="cb-filter-bar">
            <div className="cb-filter-row">
              <div className="cb-filter-group cb-filter-group--grow">
                <div className="cb-search-wrapper">
                  <i className="fas fa-search cb-search-icon"></i>
                  <input
                    id="cb-search"
                    type="text"
                    placeholder="Email, username, source…"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="cb-search-input"
                    aria-label="Search breaches"
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      className="cb-search-clear"
                      onClick={() => setSearchTerm('')}
                      aria-label="Clear search"
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  )}
                </div>
              </div>

              <button
                type="button"
                className={`cb-filter-toggle-btn${activeFilterCount > 0 ? ' cb-filter-toggle-btn--active' : ''}`}
                onClick={() => setFilterDrawerOpen(true)}
                aria-label="Open filters"
              >
                <i className="fas fa-sliders-h"></i>
                Filters
                {activeFilterCount > 0 && (
                  <span className="cb-filter-badge">{activeFilterCount}</span>
                )}
              </button>

              {hasActiveFilters && (
                <button
                  type="button"
                  className="cb-reset-btn"
                  onClick={clearAllFilters}
                  title="Clear all filters"
                >
                  <i className="fas fa-filter-circle-xmark"></i>
                  Reset
                </button>
              )}
            </div>
          </div>

          {/* Filter drawer */}
          {drawerMounted && createPortal(
            <>
            {filterDrawerOpen && (
              <div
                className="cb-drawer-backdrop"
                onClick={() => setFilterDrawerOpen(false)}
                aria-hidden="true"
              />
            )}
            <div className={`cb-filter-drawer${filterDrawerOpen ? ' cb-filter-drawer--open' : ''}`} role="dialog" aria-label="Filters">
              <div className="cb-drawer-header">
                <span className="cb-drawer-title">
                  <i className="fas fa-sliders-h"></i>
                  Filters
                  {activeFilterCount > 0 && (
                    <span className="cb-filter-badge cb-filter-badge--drawer">{activeFilterCount}</span>
                  )}
                </span>
                <button
                  type="button"
                  className="cb-drawer-close"
                  onClick={() => setFilterDrawerOpen(false)}
                  aria-label="Close filters"
                >
                  <i className="fas fa-times"></i>
                </button>
              </div>

              <div className="cb-drawer-body">
                <div className="cb-drawer-field">
                  <label className="cb-filter-label" htmlFor="cb-org-filter">
                    <i className="fas fa-building"></i>
                    Organization
                  </label>
                  <select
                    id="cb-org-filter"
                    value={orgFilter}
                    onChange={(e) => setOrgFilter(e.target.value as BreachMonitorOrgFilter)}
                    className="cb-select cb-select--full"
                    aria-label="Filter by organization"
                  >
                    <option value="all">All Organizations</option>
                    {employeeDomains.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="cb-drawer-field">
                  <label className="cb-filter-label" htmlFor="cb-slack-ignore-filter">
                    <i className="fas fa-bell-slash"></i>
                    Slack alerts
                  </label>
                  <select
                    id="cb-slack-ignore-filter"
                    value={slackIgnoreFilter}
                    onChange={(e) => setSlackIgnoreFilter(e.target.value as SlackIgnoreFilter)}
                    className="cb-select cb-select--full"
                    aria-label="Show or hide Slack-ignored breach records"
                  >
                    <option value="all">All records</option>
                    <option value="hide_ignored">Hide ignored</option>
                    <option value="ignored_only">Ignored only</option>
                  </select>
                </div>

                <div className="cb-drawer-field">
                  <label className="cb-filter-label" htmlFor="cb-intel-type-filter">
                    <i className="fas fa-network-wired"></i>
                    Intel type
                  </label>
                  <select
                    id="cb-intel-type-filter"
                    value={intelTypeFilter}
                    onChange={(e) => setIntelTypeFilter(e.target.value as BreachMonitorIntelTypeFilter)}
                    className="cb-select cb-select--full"
                    aria-label="Filter by botnet versus other breach types"
                  >
                    <option value="all">All types</option>
                    <option value="botnet">Botnet / infostealer</option>
                    <option value="other">Other (breaches, etc.)</option>
                  </select>
                </div>

                <div className="cb-drawer-field">
                  <label className="cb-filter-label" htmlFor="cb-password-filter">
                    <i className="fas fa-key"></i>
                    Password
                  </label>
                  <select
                    id="cb-password-filter"
                    value={passwordFilter}
                    onChange={(e) => setPasswordFilter(e.target.value as PasswordExposureFilter)}
                    className="cb-select cb-select--full"
                    aria-label="Filter by password exposure"
                  >
                    <option value="all">All records</option>
                    <option value="with_password">Password exposed</option>
                    <option value="without_password">No password</option>
                  </select>
                </div>

                <div className="cb-drawer-field">
                  <label className="cb-filter-label" htmlFor="cb-resolve-status-filter">
                    <i className="fas fa-check-circle"></i>
                    Resolution status
                  </label>
                  <select
                    id="cb-resolve-status-filter"
                    value={resolveStatusFilter}
                    onChange={(e) => setResolveStatusFilter(e.target.value as ResolveStatusFilter)}
                    className="cb-select cb-select--full"
                    aria-label="Filter by resolution status"
                  >
                    <option value="all">All records</option>
                    <option value="active">Active only</option>
                    <option value="resolved">Resolved only</option>
                    <option value="false_positive">False positives only</option>
                  </select>
                </div>

                {onDateFromChange && onDateToChange && (
                  <div className="cb-drawer-field">
                    <label className="cb-filter-label" htmlFor="cb-date-field">
                      <i className="fas fa-calendar-alt"></i>
                      Date range
                    </label>
                    <select
                      id="cb-date-field"
                      value={dateField}
                      onChange={(e) =>
                        onDateFieldChange?.(e.target.value as BreachMonitorDateField)
                      }
                      className="cb-select cb-select--full"
                      aria-label="Filter by ingested or exposure date"
                      disabled={!onDateFieldChange}
                    >
                      <option value="ingested">Ingested date</option>
                      <option value="exposure">Exposure date</option>
                    </select>
                    <div className="cb-date-field" style={{ marginTop: '0.4rem' }}>
                      <span className="cb-date-prefix">From</span>
                      <input
                        type="date"
                        value={dateFrom}
                        onChange={(e) => onDateFromChange(e.target.value)}
                        className="cb-date-input"
                        aria-label={
                          dateField === 'exposure'
                            ? 'Filter from exposure date'
                            : 'Filter from ingested date'
                        }
                      />
                    </div>
                    <div className="cb-date-field" style={{ marginTop: '0.4rem' }}>
                      <span className="cb-date-prefix">To</span>
                      <input
                        type="date"
                        value={dateTo}
                        onChange={(e) => onDateToChange(e.target.value)}
                        className="cb-date-input"
                        aria-label={
                          dateField === 'exposure'
                            ? 'Filter to exposure date'
                            : 'Filter to ingested date'
                        }
                      />
                    </div>
                  </div>
                )}
              </div>

              {activeFilterCount > 0 && (
                <div className="cb-drawer-footer">
                  <button
                    type="button"
                    className="cb-reset-btn cb-reset-btn--full"
                    onClick={clearAllFilters}
                  >
                    <i className="fas fa-filter-circle-xmark"></i>
                    Clear all filters
                  </button>
                </div>
              )}
            </div>
            </>,
            document.body,
          )}

          {/* Bulk action bar – admin only, visible when rows are selected */}
          {isAdmin && selectedRows.size > 0 && (() => {
            const selectedBreaches = Array.from(selectedRows).map(i => filteredBreaches[i]).filter(Boolean);
            const hasAnyActive = selectedBreaches.some(b => (b.status || 'active') === 'active');
            const hasAnyResolved = selectedBreaches.some(b => b.status === 'resolved');
            const hasAnyFalsePositive = selectedBreaches.some(b => b.status === 'false_positive');
            const hasAnyNonFalsePositive = selectedBreaches.some(b => b.status !== 'false_positive');
            return (
              <div className="cb-bulk-bar">
                <span className="cb-bulk-count">
                  <i className="fas fa-check-square"></i>
                  {selectedRows.size} row{selectedRows.size !== 1 ? 's' : ''} selected
                </span>
                <div className="cb-bulk-actions">
                  {hasAnyActive && (
                    <button
                      type="button"
                      className="btn btn-sm cb-bulk-resolve-btn"
                      onClick={() => handleBulkResolveAction('resolve')}
                      disabled={bulkResolveLoading}
                      title="Mark selected breaches as resolved"
                    >
                      <i className={bulkResolveLoading ? 'fas fa-spinner fa-spin' : 'fas fa-check-circle'}></i>
                      Resolve
                    </button>
                  )}
                  {hasAnyResolved && (
                    <button
                      type="button"
                      className="btn btn-sm cb-bulk-unresolve-btn"
                      onClick={() => handleBulkResolveAction('unresolve')}
                      disabled={bulkResolveLoading}
                      title="Reopen selected breaches as active"
                    >
                      <i className={bulkResolveLoading ? 'fas fa-spinner fa-spin' : 'fas fa-undo'}></i>
                      Unresolve
                    </button>
                  )}
                  {hasAnyNonFalsePositive && (
                    <button
                      type="button"
                      className="btn btn-sm cb-bulk-fp-btn"
                      onClick={() => handleBulkFalsePositiveAction('mark')}
                      disabled={bulkFpLoading}
                      title="Mark selected breaches as false positives"
                    >
                      <i className={bulkFpLoading ? 'fas fa-spinner fa-spin' : 'fas fa-ban'}></i>
                      False Positive
                    </button>
                  )}
                  {hasAnyFalsePositive && (
                    <button
                      type="button"
                      className="btn btn-sm cb-bulk-unfp-btn"
                      onClick={() => handleBulkFalsePositiveAction('unmark')}
                      disabled={bulkFpLoading}
                      title="Reopen false positive breaches as active"
                    >
                      <i className={bulkFpLoading ? 'fas fa-spinner fa-spin' : 'fas fa-undo'}></i>
                      Unmark FP
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm cb-bulk-ignore-btn"
                    onClick={handleBulkIgnore}
                    title="Add selected emails to the ignore list"
                  >
                    <i className="fas fa-bell-slash"></i>
                    Ignore
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm cb-bulk-clear-btn"
                    onClick={() => setSelectedRows(new Set())}
                    title="Clear selection"
                  >
                    <i className="fas fa-times"></i>
                    Clear
                  </button>
                </div>
              </div>
            );
          })()}

          {/* Table / states */}
          <div className="widget-content cb-table-content">
            {loading ? (
              <div className="cb-empty-state">
                <div className="cb-empty-icon cb-empty-icon--spin">
                  <i className="fas fa-spinner fa-spin"></i>
                </div>
                <p className="cb-empty-text">Loading breach records…</p>
              </div>
            ) : filteredBreaches.length === 0 ? (
              <div className="cb-empty-state">
                <div className="cb-empty-icon">
                  <i className="fas fa-shield-alt"></i>
                </div>
                <p className="cb-empty-text">
                  {searchTerm
                    ? 'No breaches match your search criteria.'
                    : slackIgnoreFilter === 'ignored_only'
                      ? 'No Slack-ignored records in this view.'
                      : slackIgnoreFilter === 'hide_ignored' &&
                        orgFilteredBreaches.length > 0 &&
                        slackFilteredBreaches.length === 0
                        ? 'Every record here is Slack-ignored. Choose “All records” or “Ignored only” to see them.'
                        : intelTypeFilter === 'botnet' &&
                          typeFilteredBreaches.length === 0 &&
                          slackFilteredBreaches.length > 0
                          ? 'No botnet / infostealer records in this view. Try “Other” or “All types”.'
                          : intelTypeFilter === 'other' &&
                            typeFilteredBreaches.length === 0 &&
                            slackFilteredBreaches.length > 0
                            ? 'No non-botnet records in this view. Try “Botnet / infostealer” or “All types”.'
                            : viewBreaches.length === 0
                              ? leakView === 'clients'
                                ? 'No client breach records found.'
                                : 'No employee breach records found.'
                              : orgFilter !== 'all'
                              ? 'No breaches found for this organization.'
                              : 'No breach records found.'}
                </p>
                {hasActiveFilters && (
                  <button type="button" className="cb-reset-btn" onClick={clearAllFilters}>
                    Clear filters
                  </button>
                )}
              </div>
            ) : (
              <div className="vulnerability-table-container">
                <table className="vulnerability-table cb-table">
                  <thead>
                    <tr>
                      {isAdmin && (
                        <th className="cb-th-checkbox" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            className="cb-checkbox"
                            checked={filteredBreaches.length > 0 && selectedRows.size === filteredBreaches.length}
                            ref={(el) => {
                              if (el) el.indeterminate = selectedRows.size > 0 && selectedRows.size < filteredBreaches.length;
                            }}
                            onChange={toggleSelectAll}
                            aria-label="Select all rows"
                            title="Select all"
                          />
                        </th>
                      )}
                      <th>Email / Username</th>
                      <th>Web Address</th>
                      <th>Source</th>
                      <th>Type</th>
                      <th>Confidence</th>
                      <th>Ingested</th>
                      <th>Password</th>
                      <th className="cb-th-actions">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredBreaches.map((breach, index) => (
                      <tr
                        key={index}
                        className={`breach-row breach-row-clickable${selectedRows.has(index) ? ' cb-row-selected' : ''}${breach.slack_notifications_suppressed ? ' cb-row-slack-ignored' : ''}${breach.status === 'resolved' ? ' cb-row-resolved' : ''}${breach.status === 'false_positive' ? ' cb-row-false-positive' : ''}`}
                        tabIndex={0}
                        onClick={() => openDetailModal(breach)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            openDetailModal(breach);
                          }
                        }}
                        aria-label={`Open breach details for ${breach.information.email || breach.information.username || 'this record'}${breach.slack_notifications_suppressed ? '. Slack alerts ignored for this record.' : ''}`}
                      >
                        {/* Checkbox */}
                        {isAdmin && (
                          <td className="cb-td-checkbox" onClick={(e) => toggleRowSelection(index, e)}>
                            <input
                              type="checkbox"
                              className="cb-checkbox"
                              checked={selectedRows.has(index)}
                              onChange={(e) => toggleRowSelection(index, e)}
                              onClick={(e) => e.stopPropagation()}
                              aria-label={`Select row for ${breach.information.email || breach.information.username || 'this record'}`}
                            />
                          </td>
                        )}

                        {/* Email / Username */}
                        <td>
                          <div className="cb-identity">
                            {breach.information.email ? (
                              <>
                                <span className="cb-email">{breach.information.email}</span>
                                {breach.information.username && (
                                  <span className="cb-username">{breach.information.username}</span>
                                )}
                              </>
                            ) : (
                              <span className="cb-email">{breach.information.username || '—'}</span>
                            )}
                            {breach.information.domain && (
                              <span className="cb-domain-tag">{breach.information.domain}</span>
                            )}
                            {breach.slack_notifications_suppressed ? (
                              <span
                                className="cb-ignored-inline"
                                title="Slack alerts are suppressed for this record per your ignore list."
                              >
                                <i className="fas fa-bell-slash" aria-hidden />
                                ignored
                              </span>
                            ) : null}
                            {breach.status === 'resolved' ? (
                              <span
                                className="cb-resolved-badge"
                                title={`Resolved${breach.resolved_at ? ` on ${breach.resolved_at.slice(0, 10)}` : ''}${breach.resolved_by ? ` by ${breach.resolved_by}` : ''}`}
                              >
                                <i className="fas fa-check-circle" aria-hidden />
                                Resolved
                              </span>
                            ) : null}
                            {breach.status === 'false_positive' ? (
                              <span
                                className="cb-fp-badge"
                                title={`False positive${breach.false_positive_at ? ` on ${breach.false_positive_at.slice(0, 10)}` : ''}${breach.false_positive_by ? ` by ${breach.false_positive_by}` : ''}`}
                              >
                                <i className="fas fa-ban" aria-hidden />
                                False Positive
                              </span>
                            ) : null}
                          </div>
                        </td>

                        {/* Web Address */}
                        <td onClick={(e) => e.stopPropagation()}>
                          {breach.information.web_address ? (
                            <a
                              className="cb-web-address-link"
                              href={breach.information.web_address.startsWith('http') ? breach.information.web_address : `https://${breach.information.web_address}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              title={breach.information.web_address}
                              onClick={(e) => e.stopPropagation()}
                            >
                              <i className="fas fa-external-link-alt" aria-hidden />
                              <span className="cb-web-address-text">{breach.information.web_address}</span>
                            </a>
                          ) : (
                            <span className="cb-muted">—</span>
                          )}
                        </td>

                        {/* Source */}
                        <td>
                          <div className="cb-source">
                            <span className="cb-source-name">{breach.source.name}</span>
                            <span className="cb-source-desc">
                              {(breach.source.description || '').substring(0, 80)}
                              {breach.source.description?.length > 80 ? '…' : ''}
                            </span>
                          </div>
                        </td>

                        {/* Breach Type */}
                        <td>
                          {breach.source.breach_type ? (
                            <span className="cb-badge cb-badge--type">
                              {breach.source.breach_type}
                            </span>
                          ) : (
                            <span className="cb-muted">—</span>
                          )}
                        </td>

                        {/* Confidence */}
                        <td>
                          {breach.source.confidence ? (
                            <span className={`cb-badge ${getConfidenceBadgeClass(breach.source.confidence)}`}>
                              {breach.source.confidence}
                            </span>
                          ) : (
                            <span className="cb-muted">—</span>
                          )}
                        </td>

                        {/* Date (ingestion — newest first) */}
                        <td>
                          <span className="cb-date">
                            {formatDate(breach.source.ingested_date || breach.information.date)}
                          </span>
                        </td>

                        {/* Password Exposed */}
                        <td>
                          {breach.information.password ? (
                            <span className="cb-badge cb-badge--danger">
                              <i className="fas fa-key"></i> Exposed
                            </span>
                          ) : (
                            <span className="cb-badge cb-badge--safe">
                              <i className="fas fa-check"></i> No
                            </span>
                          )}
                        </td>

                        {/* Actions */}
                        <td onClick={(e) => e.stopPropagation()}>
                          <div className="cb-action-cell">
                            <button
                              type="button"
                              className="cb-view-btn"
                              onClick={() => openDetailModal(breach)}
                              title="View full details"
                            >
                              <i className="fas fa-eye"></i>
                              <span>Details</span>
                            </button>
                            {isAdmin && breach.breach_monitor_uid && (
                              <button
                                type="button"
                                className={`cb-resolve-btn ${breach.status === 'resolved' ? 'cb-resolve-btn--unresolve' : 'cb-resolve-btn--resolve'}`}
                                onClick={(e) => handleToggleResolve(breach, e)}
                                disabled={resolveLoadingUids.has(breach.breach_monitor_uid!)}
                                title={breach.status === 'resolved' ? 'Reopen as active' : 'Mark as resolved'}
                              >
                                <i className={resolveLoadingUids.has(breach.breach_monitor_uid!) ? 'fas fa-spinner fa-spin' : breach.status === 'resolved' ? 'fas fa-undo' : 'fas fa-check-circle'}></i>
                                <span>{breach.status === 'resolved' ? 'Unresolve' : 'Resolve'}</span>
                              </button>
                            )}
                            {isAdmin && breach.breach_monitor_uid && (
                              <button
                                type="button"
                                className={`cb-fp-btn ${breach.status === 'false_positive' ? 'cb-fp-btn--unmark' : 'cb-fp-btn--mark'}`}
                                onClick={(e) => handleToggleFalsePositive(breach, e)}
                                disabled={fpLoadingUids.has(breach.breach_monitor_uid!)}
                                title={breach.status === 'false_positive' ? 'Reopen as active' : 'Mark as false positive'}
                              >
                                <i className={fpLoadingUids.has(breach.breach_monitor_uid!) ? 'fas fa-spinner fa-spin' : breach.status === 'false_positive' ? 'fas fa-undo' : 'fas fa-ban'}></i>
                                <span>{breach.status === 'false_positive' ? 'Unmark FP' : 'False Positive'}</span>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Detail Modal ── */}
      {detailModal.isOpen && detailModal.breach && (
        <div className="modal-overlay" onClick={closeDetailModal}>
          <div className="modal-content large-modal cb-detail-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>
                <i className="fas fa-file-alt"></i>
                Credential Leak Details
              </h2>
              <button className="modal-close-btn" onClick={closeDetailModal}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body cb-modal-body">
              {/* Identity banner */}
              <div className="cb-modal-banner">
                <div className="cb-modal-avatar">
                  <i className="fas fa-user-shield"></i>
                </div>
                <div className="cb-modal-identity">
                  <p className="cb-modal-email">
                    {detailModal.breach.information.email || detailModal.breach.information.username || 'Unknown'}
                  </p>
                  <div className="cb-modal-meta">
                    {detailModal.breach.information.domain && (
                      <span className="cb-modal-tag">
                        <i className="fas fa-globe"></i>
                        {detailModal.breach.information.domain}
                      </span>
                    )}
                    <span className={`cb-badge ${getConfidenceBadgeClass(detailModal.breach.source.confidence)}`}>
                      {detailModal.breach.source.confidence || 'Unknown'} confidence
                    </span>
                    {detailModal.breach.information.password ? (
                      <span className="cb-badge cb-badge--danger">
                        <i className="fas fa-key"></i> Password Exposed
                      </span>
                    ) : null}
                    {detailModal.breach.slack_notifications_suppressed ? (
                      <span
                        className="cb-badge cb-badge--slack-ignore"
                        title="Slack alerts are suppressed for this account and breach source per your ignore list."
                      >
                        <i className="fas fa-bell-slash"></i> Ignored
                      </span>
                    ) : null}
                    {detailModal.breach.status === 'resolved' ? (
                      <span
                        className="cb-badge cb-badge--resolved"
                        title={`Resolved${detailModal.breach.resolved_at ? ` on ${detailModal.breach.resolved_at.slice(0, 10)}` : ''}${detailModal.breach.resolved_by ? ` by ${detailModal.breach.resolved_by}` : ''}`}
                      >
                        <i className="fas fa-check-circle"></i> Resolved
                      </span>
                    ) : null}
                    {detailModal.breach.status === 'false_positive' ? (
                      <span
                        className="cb-badge cb-badge--false-positive"
                        title={`False positive${detailModal.breach.false_positive_at ? ` on ${detailModal.breach.false_positive_at.slice(0, 10)}` : ''}${detailModal.breach.false_positive_by ? ` by ${detailModal.breach.false_positive_by}` : ''}`}
                      >
                        <i className="fas fa-ban"></i> False Positive
                      </span>
                    ) : null}
                  </div>
                </div>
              </div>

              <div className="cb-modal-grid">
                {/* Basic Information */}
                <div className="cb-modal-section">
                  <h3 className="cb-modal-section-title">
                    <i className="fas fa-user"></i>
                    Identity
                  </h3>
                  <dl className="cb-detail-list">
                    <div className="cb-detail-row">
                      <dt>Email</dt>
                      <dd>{detailModal.breach.information.email || '—'}</dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Username</dt>
                      <dd>{detailModal.breach.information.username || '—'}</dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Domain</dt>
                      <dd>{detailModal.breach.information.domain || '—'}</dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Exposure Date</dt>
                      <dd>{detailModal.breach.information.date || 'Unknown'}</dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Password Exposed</dt>
                      <dd>{detailModal.breach.information.password ? 'Yes' : 'No'}</dd>
                    </div>
                    {canViewPasswords && breachIndicatesPasswordExposure(detailModal.breach) ? (
                      <div className="cb-detail-row">
                        <dt>Password </dt>
                        <dd className="cb-password-plain-cell">
                          {detailModal.breach.information.password_plain ? (
                            <span className="cb-password-plain-wrap">
                              <code className="cb-password-plain" translate="no">
                                {detailPasswordRevealed
                                  ? detailModal.breach.information.password_plain
                                  : maskPlainPassword(detailModal.breach.information.password_plain)}
                              </code>
                              <button
                                type="button"
                                className="cb-password-reveal-btn"
                                onClick={() => setDetailPasswordRevealed((v) => !v)}
                                title={detailPasswordRevealed ? 'Hide password' : 'Show password'}
                                aria-label={detailPasswordRevealed ? 'Hide password' : 'Show password'}
                                aria-pressed={detailPasswordRevealed}
                              >
                                <i
                                  className={`fas ${detailPasswordRevealed ? 'fa-eye-slash' : 'fa-eye'}`}
                                  aria-hidden
                                />
                              </button>
                            </span>
                          ) : (
                            <span className="cb-muted">Not available for this record</span>
                          )}
                        </dd>
                      </div>
                    ) : null}
                    <div className="cb-detail-row">
                      <dt>Validated</dt>
                      <dd>{detailModal.breach.validated ? 'Yes' : 'No'}</dd>
                    </div>
                  </dl>
                </div>

                {/* Source Information */}
                <div className="cb-modal-section">
                  <h3 className="cb-modal-section-title">
                    <i className="fas fa-database"></i>
                    Breach Source
                  </h3>
                  <dl className="cb-detail-list">
                    <div className="cb-detail-row">
                      <dt>Name</dt>
                      <dd><strong>{detailModal.breach.source.name}</strong></dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Breach Type</dt>
                      <dd>
                        <span className="cb-badge cb-badge--type">
                          {detailModal.breach.source.breach_type || '—'}
                        </span>
                      </dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Source</dt>
                      <dd>
                        <span className="cb-badge cb-badge--neutral">
                          {detailModal.breach.source.source || '—'}
                        </span>
                      </dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Confidence</dt>
                      <dd>
                        <span className={`cb-badge ${getConfidenceBadgeClass(detailModal.breach.source.confidence)}`}>
                          {detailModal.breach.source.confidence || '—'}
                        </span>
                      </dd>
                    </div>
                    <div className="cb-detail-row">
                      <dt>Record Type</dt>
                      <dd>{detailModal.breach.type || '—'}</dd>
                    </div>
                    {detailModal.breach.source.ingested_date && (
                      <div className="cb-detail-row">
                        <dt>Ingested Date</dt>
                        <dd>{formatDate(detailModal.breach.source.ingested_date)}</dd>
                      </div>
                    )}
                  </dl>
                </div>

                {/* Description */}
                <div className="cb-modal-section cb-modal-section--full">
                  <h3 className="cb-modal-section-title">
                    <i className="fas fa-info-circle"></i>
                    Description
                  </h3>
                  <p className="cb-prose">
                    {detailModal.breach.source.description || 'No description available.'}
                  </p>
                </div>

                {/* Recommendations */}
                <div className="cb-modal-section cb-modal-section--full cb-modal-section--recommendations">
                  <h3 className="cb-modal-section-title">
                    <i className="fas fa-shield-alt"></i>
                    Recommendations
                  </h3>
                  <p className="cb-prose">
                    {detailModal.breach.source.recommendations || 'No recommendations available.'}
                  </p>
                </div>

                {/* Web Address */}
                {detailModal.breach.information.web_address && (
                  <div className="cb-modal-section cb-modal-section--full">
                    <h3 className="cb-modal-section-title">
                      <i className="fas fa-globe"></i>
                      Web Address
                    </h3>
                    <a
                      href={/^https?:\/\//i.test(detailModal.breach.information.web_address) ? detailModal.breach.information.web_address : `https://${detailModal.breach.information.web_address}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cb-link"
                    >
                      {detailModal.breach.information.web_address}
                    </a>
                  </div>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closeDetailModal}>
                <i className="fas fa-times"></i>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Query Modal ── */}
      {queryModal.isOpen && (
        <div className="modal-overlay" onClick={closeQueryModal}>
          <div className="modal-content cb-query-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>
                <i className="fas fa-search"></i>
                Query Breaches
              </h2>
              <button className="modal-close-btn" onClick={closeQueryModal}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="cb-query-modal-body">
              {!queryModal.queryType ? (
                <div className="cb-query-type-picker">
                  <p className="cb-query-hint">Choose a query method to search the Breach Monitor breach database:</p>
                  <div className="cb-query-type-grid">
                    <button
                      className="cb-query-type-card cb-query-type-card--domain"
                      onClick={() => openQueryModal('domain')}
                    >
                      <div className="cb-query-type-icon-wrap cb-query-type-icon-wrap--domain">
                        <i className="fas fa-globe"></i>
                      </div>
                      <span className="cb-query-type-label">By Domain</span>
                      <span className="cb-query-type-desc">Search all breaches associated with a domain</span>
                    </button>
                    <button
                      className="cb-query-type-card cb-query-type-card--email"
                      onClick={() => openQueryModal('email')}
                    >
                      <div className="cb-query-type-icon-wrap cb-query-type-icon-wrap--email">
                        <i className="fas fa-envelope"></i>
                      </div>
                      <span className="cb-query-type-label">By Email</span>
                      <span className="cb-query-type-desc">Search breaches for a specific email address</span>
                    </button>
                    <button
                      className="cb-query-type-card cb-query-type-card--web-address"
                      onClick={() => openQueryModal('web_address')}
                    >
                      <div className="cb-query-type-icon-wrap cb-query-type-icon-wrap--web-address">
                        <i className="fas fa-link"></i>
                      </div>
                      <span className="cb-query-type-label">By Web Address</span>
                      <span className="cb-query-type-desc">Search botnet records for one or more URLs</span>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="cb-query-form">
                  <button
                    className="cb-back-btn"
                    onClick={() => setQueryModal(prev => ({ ...prev, queryType: null, queryValue: '', webAddressEmails: '', results: [], hasQueried: false, hasMore: false, nextId: '' }))}
                  >
                    <i className="fas fa-arrow-left"></i>
                    Back
                  </button>

                  <div className="cb-query-input-group">
                    <label className="cb-filter-label">
                      {queryModal.queryType === 'domain' ? (
                        <><i className="fas fa-globe"></i> Domain</>
                      ) : queryModal.queryType === 'web_address' ? (
                        <><i className="fas fa-link"></i> Web Address(es)</>
                      ) : (
                        <><i className="fas fa-envelope"></i> Email Address</>
                      )}
                    </label>
                    <div className="cb-search-wrapper">
                      <i className={`fas fa-${queryModal.queryType === 'domain' ? 'globe' : queryModal.queryType === 'web_address' ? 'link' : 'at'} cb-search-icon`}></i>
                      <input
                        type="text"
                        placeholder={
                          queryModal.queryType === 'domain'
                            ? 'e.g., example.com, other.com'
                            : queryModal.queryType === 'web_address'
                            ? 'e.g., auth.example.com, oauth.example.com'
                            : 'e.g., user@example.com, other@example.com'
                        }
                        value={queryModal.queryValue}
                        onChange={(e) =>
                          setQueryModal(prev => ({
                            ...prev,
                            queryValue: e.target.value,
                            hasQueried: false,
                            results: [],
                            hasMore: false,
                            nextId: '',
                          }))
                        }
                        onKeyPress={(e) => e.key === 'Enter' && executeQuery()}
                        className="cb-search-input"
                      />
                    </div>
                    {queryModal.queryType === 'domain' && (
                      <p className="cb-query-hint" style={{ marginTop: '0.4rem', fontSize: '0.78rem' }}>
                        Separate multiple domains with commas.
                      </p>
                    )}
                    {queryModal.queryType === 'email' && (
                      <p className="cb-query-hint" style={{ marginTop: '0.4rem', fontSize: '0.78rem' }}>
                        Separate multiple email addresses with commas.
                      </p>
                    )}
                    {queryModal.queryType === 'web_address' && (
                      <>
                        <p className="cb-query-hint" style={{ marginTop: '0.4rem', fontSize: '0.78rem' }}>
                          Separate multiple addresses with commas. Queries the botnet (infostealer) endpoint.
                        </p>
                        <label className="cb-filter-label" style={{ marginTop: '1rem' }}>
                          <i className="fas fa-envelope"></i> Email(s) <span style={{ fontWeight: 400, opacity: 0.7 }}>(optional)</span>
                        </label>
                        <div className="cb-search-wrapper">
                          <i className="fas fa-at cb-search-icon"></i>
                          <input
                            type="text"
                            placeholder="e.g., user@example.com, other@example.com"
                            value={queryModal.webAddressEmails}
                            onChange={(e) =>
                              setQueryModal(prev => ({
                                ...prev,
                                webAddressEmails: e.target.value,
                                hasQueried: false,
                                results: [],
                                hasMore: false,
                                nextId: '',
                              }))
                            }
                            onKeyPress={(e) => e.key === 'Enter' && executeQuery()}
                            className="cb-search-input"
                          />
                        </div>
                        <p className="cb-query-hint" style={{ marginTop: '0.4rem', fontSize: '0.78rem' }}>
                          Optionally narrow results to specific email addresses (comma-separated).
                        </p>
                      </>
                    )}
                  </div>

                  <button
                    className="btn btn-primary cb-query-submit"
                    onClick={() => executeQuery()}
                    disabled={queryModal.loading}
                  >
                    {queryModal.loading ? (
                      <><i className="fas fa-spinner fa-spin"></i> Searching…</>
                    ) : (
                      <><i className="fas fa-search"></i> Search</>
                    )}
                  </button>

                  {queryModal.hasQueried && queryModal.results.length === 0 && !queryModal.loading && (
                    <div className="cb-query-no-results">
                      <div className="cb-query-no-results-icon">
                        <i className="fas fa-search"></i>
                      </div>
                      <p className="cb-query-no-results-title">No results found</p>
                      <p className="cb-query-no-results-sub">
                        No breach records were found for{' '}
                        <strong>
                          {queryModal.queryType === 'domain' ? 'domain' : queryModal.queryType === 'web_address' ? 'web address' : 'email'}{' '}
                          &ldquo;{queryModal.queryValue}&rdquo;
                        </strong>
                        . Try a different{' '}
                        {queryModal.queryType === 'domain' ? 'domain name' : queryModal.queryType === 'web_address' ? 'web address' : 'email address'}.
                      </p>
                    </div>
                  )}

                  {queryModal.results.length > 0 && (
                    <div className="cb-query-results">
                      <p className="cb-query-results-count">
                        <i className="fas fa-check-circle cb-results-found-icon"></i>
                        {queryModal.results.length} result{queryModal.results.length !== 1 ? 's' : ''} found
                      </p>
                      <div className="cb-query-results-list">
                        {queryModal.results.map((breach, index) => {
                          const passwordRevealUid =
                            (breach.information.uid && String(breach.information.uid).trim()) ||
                            `q-pw-${index}`;
                          const queryPwShown = queryPasswordRevealedUids.has(passwordRevealUid);
                          return (
                            <div
                              key={index}
                              className={`cb-query-result-card${breach.slack_notifications_suppressed ? ' cb-query-result-card--ignored' : ''
                                }`}
                              onClick={() => setExpandedBreachIndex(expandedBreachIndex === index ? null : index)}
                            >
                              <div className="cb-query-result-header">
                                <div>
                                  <p className="cb-query-result-email">
                                    {breach.information.email || breach.information.username || '—'}
                                  </p>
                                  <p className="cb-query-result-meta">
                                    <strong>{breach.source.name}</strong>
                                    {breach.information.date ? ` · ${formatDate(breach.information.date)}` : ''}
                                  </p>
                                </div>
                                <div className="cb-query-result-badges">
                                  {breach.slack_notifications_suppressed ? (
                                    <span
                                      className="cb-badge cb-badge--slack-ignore"
                                      title="Slack alerts suppressed per ignore list"
                                    >
                                      <i className="fas fa-bell-slash" aria-hidden />
                                      Ignored
                                    </span>
                                  ) : null}
                                  <span className={`cb-badge ${getConfidenceBadgeClass(breach.source.confidence)}`}>
                                    {breach.source.confidence || '—'}
                                  </span>
                                  <i className={`fas fa-chevron-${expandedBreachIndex === index ? 'up' : 'down'} cb-chevron`}></i>
                                </div>
                              </div>

                              {expandedBreachIndex === index && (
                                <div className="cb-query-result-expanded" onClick={(e) => e.stopPropagation()}>
                                  <div className="cb-modal-grid">
                                    {/* Identity */}
                                    <div className="cb-modal-section">
                                      <h3 className="cb-modal-section-title">
                                        <i className="fas fa-user"></i>
                                        Identity
                                      </h3>
                                      <dl className="cb-detail-list">
                                        <div className="cb-detail-row">
                                          <dt>Email</dt>
                                          <dd>{breach.information.email || '—'}</dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Username</dt>
                                          <dd>{breach.information.username || '—'}</dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Domain</dt>
                                          <dd>{breach.information.domain || '—'}</dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Exposure Date</dt>
                                          <dd>{breach.information.date ? formatDate(breach.information.date) : 'Unknown'}</dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Password Exposed</dt>
                                          <dd>{breach.information.password ? 'Yes' : 'No'}</dd>
                                        </div>
                                        {canViewPasswords && breachIndicatesPasswordExposure(breach) ? (
                                          <div className="cb-detail-row">
                                            <dt>Password</dt>
                                            <dd className="cb-password-plain-cell">
                                              {breach.information.password_plain ? (
                                                <span className="cb-password-plain-wrap">
                                                  <code className="cb-password-plain" translate="no">
                                                    {queryPwShown
                                                      ? breach.information.password_plain
                                                      : maskPlainPassword(breach.information.password_plain)}
                                                  </code>
                                                  <button
                                                    type="button"
                                                    className="cb-password-reveal-btn"
                                                    onClick={() => toggleQueryPasswordReveal(passwordRevealUid)}
                                                    title={queryPwShown ? 'Hide password' : 'Show password'}
                                                    aria-label={queryPwShown ? 'Hide password' : 'Show password'}
                                                    aria-pressed={queryPwShown}
                                                  >
                                                    <i className={`fas ${queryPwShown ? 'fa-eye-slash' : 'fa-eye'}`} aria-hidden />
                                                  </button>
                                                </span>
                                              ) : (
                                                <span className="cb-muted">Not available for this record</span>
                                              )}
                                            </dd>
                                          </div>
                                        ) : null}
                                        <div className="cb-detail-row">
                                          <dt>Validated</dt>
                                          <dd>{breach.validated ? 'Yes' : 'No'}</dd>
                                        </div>
                                      </dl>
                                    </div>

                                    {/* Breach Source */}
                                    <div className="cb-modal-section">
                                      <h3 className="cb-modal-section-title">
                                        <i className="fas fa-database"></i>
                                        Breach Source
                                      </h3>
                                      <dl className="cb-detail-list">
                                        <div className="cb-detail-row">
                                          <dt>Name</dt>
                                          <dd><strong>{breach.source.name || '—'}</strong></dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Breach Type</dt>
                                          <dd>
                                            <span className="cb-badge cb-badge--type">{breach.source.breach_type || '—'}</span>
                                          </dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Source</dt>
                                          <dd>
                                            <span className="cb-badge cb-badge--neutral">{breach.source.source || '—'}</span>
                                          </dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Confidence</dt>
                                          <dd>
                                            <span className={`cb-badge ${getConfidenceBadgeClass(breach.source.confidence)}`}>
                                              {breach.source.confidence || '—'}
                                            </span>
                                          </dd>
                                        </div>
                                        <div className="cb-detail-row">
                                          <dt>Record Type</dt>
                                          <dd>{breach.type || '—'}</dd>
                                        </div>
                                        {breach.source.ingested_date && (
                                          <div className="cb-detail-row">
                                            <dt>Ingested Date</dt>
                                            <dd>{formatDate(breach.source.ingested_date)}</dd>
                                          </div>
                                        )}
                                      </dl>
                                    </div>

                                    {/* Description */}
                                    <div className="cb-modal-section cb-modal-section--full">
                                      <h3 className="cb-modal-section-title">
                                        <i className="fas fa-info-circle"></i>
                                        Description
                                      </h3>
                                      <p className="cb-prose">{breach.source.description || 'No description available.'}</p>
                                    </div>

                                    {/* Recommendations */}
                                    <div className="cb-modal-section cb-modal-section--full cb-modal-section--recommendations">
                                      <h3 className="cb-modal-section-title">
                                        <i className="fas fa-shield-alt"></i>
                                        Recommendations
                                      </h3>
                                      <p className="cb-prose">{breach.source.recommendations || 'No recommendations available.'}</p>
                                    </div>

                                    {/* Web Address */}
                                    {breach.information.web_address && (
                                      <div className="cb-modal-section cb-modal-section--full">
                                        <h3 className="cb-modal-section-title">
                                          <i className="fas fa-globe"></i>
                                          Web Address
                                        </h3>
                                        <a
                                          href={/^https?:\/\//i.test(breach.information.web_address) ? breach.information.web_address : `https://${breach.information.web_address}`}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="cb-link"
                                        >
                                          {breach.information.web_address}
                                        </a>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>

                      {queryModal.hasMore && (
                        <button
                          type="button"
                          className="btn btn-secondary cb-load-more"
                          onClick={() => executeQuery(queryModal.nextId)}
                          disabled={queryModal.loading}
                        >
                          {queryModal.loading ? (
                            <><i className="fas fa-spinner fa-spin" /> Loading…</>
                          ) : (
                            <>Load more results</>
                          )}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Ignore List Modal ── */}
      {ignoreListOpen && (
        <div className="modal-overlay" onClick={closeIgnoreList}>
          <div className="modal-content cb-ignore-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>
                <i className="fas fa-bell-slash"></i>
                Alert Ignore List
              </h2>
              <button className="modal-close-btn" onClick={closeIgnoreList}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            {/* Tab bar */}
            <div className="cb-ignore-tabs">
              <button
                className={`cb-ignore-tab${ignoreListView === 'list' ? ' cb-ignore-tab--active' : ''}`}
                onClick={() => { setIgnoreListView('list'); setDeleteConfirmId(null); }}
              >
                <i className="fas fa-list"></i>
                View List
                {ignoreListEntries.length > 0 && (
                  <span className="cb-ignore-tab-badge">{ignoreListEntries.length}</span>
                )}
              </button>
              <button
                className={`cb-ignore-tab${ignoreListView === 'add' ? ' cb-ignore-tab--active' : ''}`}
                onClick={() => openAddView()}
              >
                <i className="fas fa-plus"></i>
                Add Entry
              </button>
            </div>

            <div className="modal-body cb-ignore-body">
              {/* ── LIST VIEW ── */}
              {ignoreListView === 'list' && (
                <>
                  {ignoreListError && (
                    <div className="cb-ignore-error">
                      <i className="fas fa-exclamation-circle"></i>
                      {ignoreListError}
                    </div>
                  )}

                  {ignoreListLoading ? (
                    <div className="cb-empty-state">
                      <div className="cb-empty-icon cb-empty-icon--spin">
                        <i className="fas fa-spinner fa-spin"></i>
                      </div>
                      <p className="cb-empty-text">Loading ignore list…</p>
                    </div>
                  ) : ignoreListEntries.length === 0 ? (
                    <div className="cb-empty-state">
                      <div className="cb-empty-icon">
                        <i className="fas fa-bell"></i>
                      </div>
                      <p className="cb-empty-text">No entries yet. Add one to suppress Slack alerts.</p>
                      <button type="button" className="btn btn-primary btn-sm" onClick={() => openAddView()}>
                        <i className="fas fa-plus"></i> Add Entry
                      </button>
                    </div>
                  ) : (
                    <div className="cb-ignore-list">
                      {ignoreListEntries.map(entry => (
                        <div key={entry.id} className="cb-ignore-entry">
                          <div className="cb-ignore-entry-top">
                            <div className="cb-ignore-entry-info">
                              <span className="cb-ignore-email">
                                <i className="fas fa-envelope"></i>
                                {entry.email}
                              </span>
                              {entry.notes && (
                                <span className="cb-ignore-notes">{entry.notes}</span>
                              )}
                              {entry.created_by && (
                                <span className="cb-ignore-meta">Added by {entry.created_by}</span>
                              )}
                            </div>
                            <div className="cb-ignore-entry-actions">
                              <button
                                type="button"
                                className={`cb-ignore-delete-btn${deleteConfirmId === entry.id ? ' cb-ignore-delete-btn--confirm' : ''}`}
                                onClick={() => handleDeleteEntry(entry.id)}
                                title={deleteConfirmId === entry.id ? 'Click again to confirm deletion' : 'Remove entry'}
                              >
                                {deleteConfirmId === entry.id ? (
                                  <><i className="fas fa-exclamation-triangle"></i> Confirm</>
                                ) : (
                                  <><i className="fas fa-trash"></i></>
                                )}
                              </button>
                              {deleteConfirmId === entry.id && (
                                <button
                                  type="button"
                                  className="cb-ignore-cancel-btn"
                                  onClick={() => setDeleteConfirmId(null)}
                                >
                                  Cancel
                                </button>
                              )}
                            </div>
                          </div>
                          <div className="cb-ignore-scope">
                            {entry.incident_names.length === 0 && (entry.passwords || []).length === 0 ? (
                              <span className="cb-ignore-scope-all">
                                <i className="fas fa-ban"></i>
                                All leaks suppressed
                              </span>
                            ) : (
                              <div className="cb-ignore-incidents">
                                {entry.incident_names.map(n => (
                                  <span key={n} className="cb-ignore-incident-tag">{n}</span>
                                ))}
                                {(entry.passwords || []).map(p => {
                                  const masked = p.length <= 3 ? '•'.repeat(p.length) : '•'.repeat(Math.min(p.length - 3, 6)) + p.slice(-3);
                                  return (
                                    <span key={p} className="cb-ignore-incident-tag cb-ignore-password-tag cb-ignore-password-mono" title="Password (partially masked)">
                                      <i className="fas fa-lock" style={{ fontSize: '0.65rem', marginRight: '0.2rem' }}></i>
                                      {masked}
                                    </span>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {/* ── ADD VIEW ── */}
              {ignoreListView === 'add' && (
                <div className="cb-ignore-add-form">
                  {addSuccess && (
                    <div className="cb-ignore-success">
                      <i className="fas fa-check-circle"></i>
                      Entry saved successfully!
                    </div>
                  )}
                  {addError && (
                    <div className="cb-ignore-error">
                      <i className="fas fa-exclamation-circle"></i>
                      {addError}
                    </div>
                  )}

                  <div className="cb-ignore-field">
                    <label className="cb-filter-label">
                      <i className="fas fa-envelope"></i>
                      Email Addresses <span className="cb-ignore-required">*</span>
                    </label>
                    <div
                      className="cb-email-tags-input"
                      onClick={() => (document.getElementById('cb-ignore-email-input') as HTMLInputElement | null)?.focus()}
                    >
                      {addEmails.map(email => (
                        <span key={email} className="cb-email-tag">
                          {email}
                          <button
                            type="button"
                            className="cb-email-tag-remove"
                            onClick={(e) => { e.stopPropagation(); removeEmail(email); }}
                            aria-label={`Remove ${email}`}
                          >
                            <i className="fas fa-times"></i>
                          </button>
                        </span>
                      ))}
                      <input
                        id="cb-ignore-email-input"
                        type="text"
                        className="cb-email-tags-field"
                        placeholder={addEmails.length === 0 ? 'user@example.com, another@example.com…' : 'Add another…'}
                        value={addEmailInput}
                        onChange={e => { setAddEmailInput(e.target.value); setAddError(null); }}
                        onKeyDown={handleEmailKeyDown}
                        onBlur={commitEmailInput}
                        autoComplete="off"
                      />
                    </div>
                  </div>

                  <div className="cb-ignore-field">
                    <label className="cb-filter-label">
                      <i className="fas fa-database"></i>
                      Leaks to suppress
                      <span className="cb-ignore-optional">(optional — leave empty to suppress all)</span>
                    </label>

                    {incidentsLoading ? (
                      <div className="cb-ignore-incidents-loading">
                        <i className="fas fa-spinner fa-spin"></i> Loading leaks…
                      </div>
                    ) : allIncidents.length === 0 ? (
                      <p className="cb-ignore-field-hint">No breach incidents found in the database yet.</p>
                    ) : (
                      <>
                        <div className="cb-search-wrapper cb-ignore-incident-search">
                          <i className="fas fa-search cb-search-icon"></i>
                          <input
                            ref={incidentSearchRef}
                            type="text"
                            className="cb-search-input"
                            placeholder="Filter leaks…"
                            value={incidentSearchTerm}
                            onChange={e => setIncidentSearchTerm(e.target.value)}
                          />
                          {incidentSearchTerm && (
                            <button
                              type="button"
                              className="cb-search-clear"
                              onClick={() => setIncidentSearchTerm('')}
                              aria-label="Clear search"
                            >
                              <i className="fas fa-times"></i>
                            </button>
                          )}
                        </div>
                        {addSelectedIncidents.length > 0 && (
                          <div className="cb-ignore-selected-summary">
                            <span className="cb-ignore-selected-count">
                              {addSelectedIncidents.length} leak{addSelectedIncidents.length !== 1 ? 's' : ''} selected
                            </span>
                            <button
                              type="button"
                              className="cb-ignore-clear-selection"
                              onClick={() => setAddSelectedIncidents([])}
                            >
                              Clear
                            </button>
                          </div>
                        )}
                        <div className="cb-ignore-incident-list">
                          {filteredIncidents.map(name => {
                            const checked = addSelectedIncidents.includes(name);
                            return (
                              <label key={name} className={`cb-ignore-incident-item${checked ? ' cb-ignore-incident-item--checked' : ''}`}>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => toggleIncident(name)}
                                  className="cb-ignore-checkbox"
                                />
                                <span className="cb-ignore-incident-name">{name}</span>
                              </label>
                            );
                          })}
                          {filteredIncidents.length === 0 && (
                            <p className="cb-ignore-field-hint" style={{ padding: '0.5rem' }}>No leaks match your search.</p>
                          )}
                        </div>
                      </>
                    )}
                  </div>

                  {addEmails.length > 0 && (
                    <div className="cb-ignore-field">
                      <label className="cb-filter-label">
                        <i className="fas fa-lock"></i>
                        Passwords to suppress
                      </label>

                      {passwordsLoading ? (
                        <div className="cb-ignore-incidents-loading">
                          <i className="fas fa-spinner fa-spin"></i> Loading passwords…
                        </div>
                      ) : addEmails.every(e => (availablePasswordsByEmail[e] || []).length === 0) ? (
                        <p className="cb-ignore-field-hint">No passwords on record for the entered email{addEmails.length !== 1 ? 's' : ''}.</p>
                      ) : (() => {
                        const distinctPwds = Array.from(
                          new Set(addEmails.flatMap(e => availablePasswordsByEmail[e] || []))
                        ).sort();
                        return (
                          <div className="cb-ignore-incident-list">
                            {distinctPwds.map(pwd => {
                              const masked = pwd.length <= 3 ? '•'.repeat(pwd.length) : '•'.repeat(Math.min(pwd.length - 3, 6)) + pwd.slice(-3);
                              const checked = addSelectedPasswords.includes(pwd);
                              return (
                                <label key={pwd} className={`cb-ignore-incident-item${checked ? ' cb-ignore-incident-item--checked' : ''}`}>
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => setAddSelectedPasswords(prev =>
                                      prev.includes(pwd) ? prev.filter(p => p !== pwd) : [...prev, pwd]
                                    )}
                                    className="cb-ignore-checkbox"
                                  />
                                  <span className="cb-ignore-incident-name cb-ignore-password-mono">{masked}</span>
                                </label>
                              );
                            })}
                          </div>
                        );
                      })()}
                      {addSelectedPasswords.length > 0 && (
                        <div style={{ marginTop: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className="cb-ignore-selected-count">
                            {addSelectedPasswords.length} password{addSelectedPasswords.length !== 1 ? 's' : ''} selected
                          </span>
                          <button type="button" className="cb-ignore-clear-selection" onClick={() => setAddSelectedPasswords([])}>
                            Clear
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="cb-ignore-field">
                    <label className="cb-filter-label" htmlFor="cb-ignore-notes">
                      <i className="fas fa-sticky-note"></i>
                      Notes <span className="cb-ignore-optional">(optional)</span>
                    </label>
                    <input
                      id="cb-ignore-notes"
                      type="text"
                      className="cb-search-input cb-ignore-input"
                      placeholder="Reason for suppression…"
                      value={addNotes}
                      onChange={e => setAddNotes(e.target.value)}
                    />
                  </div>

                  <div className="cb-ignore-add-scope-info">
                    {addSelectedIncidents.length === 0 && addSelectedPasswords.length === 0 ? (
                      <div className="cb-ignore-scope-notice cb-ignore-scope-notice--all">
                        <i className="fas fa-ban"></i>
                        <span>With no leaks or passwords selected, <strong>all</strong> future Slack alerts for this email will be suppressed.</span>
                      </div>
                    ) : (
                      <div className="cb-ignore-scope-notice cb-ignore-scope-notice--partial">
                        <i className="fas fa-filter"></i>
                        <span>
                          Only alerts matching{' '}
                          {addSelectedIncidents.length > 0 && <><strong>{addSelectedIncidents.length}</strong> selected leak{addSelectedIncidents.length !== 1 ? 's' : ''}</>}
                          {addSelectedIncidents.length > 0 && addSelectedPasswords.length > 0 && ' or '}
                          {addSelectedPasswords.length > 0 && <><strong>{addSelectedPasswords.length}</strong> password{addSelectedPasswords.length !== 1 ? 's' : ''}</>}
                          {' '}will be suppressed. Other alerts will still be sent.
                        </span>
                      </div>
                    )}
                  </div>

                  <button
                    type="button"
                    className="btn btn-primary cb-ignore-submit"
                    onClick={handleAddSubmit}
                    disabled={addSubmitting || (addEmails.length === 0 && !addEmailInput.trim())}
                  >
                    {addSubmitting ? (
                      <><i className="fas fa-spinner fa-spin"></i> Saving…</>
                    ) : (
                      <><i className="fas fa-save"></i> Save Entry</>
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        /* ── Page header (Breach Monitor section) ── */
        :global(#breach-monitor-content .page-header) {
          padding: 0.75rem 1rem;
          margin-bottom: 0.85rem;
        }

        :global(#breach-monitor-content .page-header h1) {
          font-size: 1.2rem;
          font-weight: 600;
          line-height: 1.3;
        }

        :global(#breach-monitor-content .page-header span) {
          font-size: 0.8rem !important;
        }

        /* ── Container ── */
        .cb-container {
          display: flex;
          flex-direction: column;
          gap: 0.85rem;
        }

        .cb-summary-widget :global(.widget-header),
        .cb-records-widget :global(.widget-header) {
          padding: 0.6rem 1rem;
        }

        .cb-summary-widget :global(.widget-content) {
          padding: 0.65rem 1rem;
        }

        /* ── Section title ── */
        .cb-section-title {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          margin: 0;
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--text-primary, #111827);
        }

        .cb-section-title .cb-icon-coral {
          font-size: 0.8rem;
        }

        .cb-icon-blue {
          color: #3b82f6;
        }

        .cb-icon-coral {
          color: var(--coral, #e8394a);
        }

        .cb-filter-tag {
          font-size: 0.7rem;
          font-weight: 500;
          background: #dbeafe;
          color: #1d4ed8;
          padding: 0.15rem 0.45rem;
          border-radius: 99px;
          letter-spacing: 0.02em;
        }

        .cb-count-badge {
          font-size: 0.68rem;
          font-weight: 600;
          background: #f3f4f6;
          color: #6b7280;
          padding: 0.1rem 0.5rem;
          border-radius: 99px;
          border: 1px solid #e5e7eb;
        }

        .cb-ignored-indicator {
          display: inline-flex;
          align-items: center;
          gap: 0.3rem;
          font-size: 0.68rem;
          font-weight: 600;
          color: #92400e;
          background: #fef3c7;
          border: 1px solid rgba(180, 83, 9, 0.35);
          padding: 0.12rem 0.55rem 0.12rem 0.45rem;
          border-radius: 99px;
          letter-spacing: 0.01em;
        }

        .cb-ignored-indicator .fa-bell-slash {
          font-size: 0.65rem;
          opacity: 0.9;
        }

        .cb-ignored-indicator__label {
          font-variant-numeric: tabular-nums;
          font-weight: 700;
        }

        /* ── Records header ── */
        .cb-records-header {
          align-items: center !important;
        }

        .cb-header-actions {
          display: flex;
          gap: 0.5rem;
          align-items: center;
          flex-shrink: 0;
        }

        .cb-action-btn {
          white-space: nowrap;
        }

        /* ── Export Excel button (matches unique-emails green, same shape as Ignore List) ── */
        .cb-export-btn {
          border-color: #bbf7d0 !important;
          color: #059669 !important;
          background: #f0fdf4 !important;
        }

        .cb-export-btn:hover:not(:disabled) {
          background: #d1fae5 !important;
          border-color: #86efac !important;
          color: #047857 !important;
        }

        :global(body.dark-mode) .cb-export-btn {
          background: #052e16 !important;
          border-color: #059669 !important;
          color: #6ee7b7 !important;
        }

        :global(body.dark-mode) .cb-export-btn:hover:not(:disabled) {
          background: #064e3b !important;
          border-color: #10b981 !important;
        }

        /* ── Stats grid ── */
        .cb-stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
          gap: 0.6rem;
        }

        .cb-stat-card {
          display: flex;
          align-items: center;
          gap: 0.65rem;
          padding: 0.6rem 0.85rem;
          border-radius: 8px;
          border: 1px solid transparent;
        }

        .cb-stat-card--total {
          background: #eff6ff;
          border-color: #bfdbfe;
        }

        .cb-stat-card--emails {
          background: #f0fdf4;
          border-color: #bbf7d0;
        }

        .cb-stat-card--sources {
          background: #fef9c3;
          border-color: #fde68a;
        }

        .cb-stat-icon {
          width: 1.85rem;
          height: 1.85rem;
          border-radius: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 0.85rem;
          flex-shrink: 0;
        }

        .cb-stat-card--total .cb-stat-icon {
          background: #dbeafe;
          color: #2563eb;
        }

        .cb-stat-card--emails .cb-stat-icon {
          background: #d1fae5;
          color: #059669;
        }

        .cb-stat-card--sources .cb-stat-icon {
          background: #fef08a;
          color: #b45309;
        }

        .cb-stat-body {
          display: flex;
          flex-direction: column;
          gap: 0.15rem;
        }

        .cb-stat-value {
          font-size: 1.15rem;
          font-weight: 700;
          color: #111827;
          line-height: 1;
        }

        .cb-stat-label {
          font-size: 0.68rem;
          color: #6b7280;
          font-weight: 500;
        }

        /* ── Filter bar ── */
        .cb-filter-bar {
          padding: 0.55rem 1rem;
          background: #f9fafb;
          border-bottom: 1px solid var(--border-color, #e5e7eb);
        }

        .cb-filter-row {
          display: flex;
          gap: 0.6rem;
          align-items: center;
        }

        .cb-filter-group {
          display: flex;
          flex-direction: column;
          gap: 0.35rem;
        }

        .cb-filter-group--grow {
          flex: 1 1 180px;
          min-width: 160px;
        }

        .cb-filter-label {
          display: flex;
          align-items: center;
          gap: 0.35rem;
          font-size: 0.72rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          color: #6b7280;
        }

        /* ── Filters toggle button ── */
        .cb-filter-toggle-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          height: 2.1rem;
          padding: 0 0.85rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          background: white;
          color: #374151;
          font-size: 0.82rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }

        .cb-filter-toggle-btn:hover {
          border-color: #3b82f6;
          color: #2563eb;
          background: #eff6ff;
        }

        .cb-filter-toggle-btn--active {
          border-color: #3b82f6;
          background: #eff6ff;
          color: #2563eb;
        }

        .cb-filter-badge {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 1.1rem;
          height: 1.1rem;
          padding: 0 0.3rem;
          border-radius: 999px;
          background: #3b82f6;
          color: white;
          font-size: 0.7rem;
          font-weight: 700;
          line-height: 1;
        }

        .cb-filter-badge--drawer {
          background: #2563eb;
        }

        /* ── Slide-in filter drawer ── */
        .cb-drawer-backdrop {
          position: fixed;
          inset: 0;
          z-index: 199;
          background: rgba(0, 0, 0, 0.25);
        }

        .cb-filter-drawer {
          position: fixed;
          top: 0;
          right: 0;
          bottom: 0;
          z-index: 200;
          width: 280px;
          background: #ffffff;
          border-left: 1px solid #e5e7eb;
          box-shadow: -4px 0 24px rgba(0, 0, 0, 0.1);
          display: flex;
          flex-direction: column;
          transform: translateX(100%);
          visibility: hidden;
          transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1),
            visibility 0s linear 0.22s;
        }

        .cb-filter-drawer--open {
          transform: translateX(0);
          visibility: visible;
          transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1),
            visibility 0s linear 0s;
        }

        .cb-drawer-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 1rem 1.25rem;
          border-bottom: 1px solid #e5e7eb;
          flex-shrink: 0;
        }

        .cb-drawer-title {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-size: 0.92rem;
          font-weight: 600;
          color: #111827;
        }

        .cb-drawer-close {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 1.75rem;
          height: 1.75rem;
          border: none;
          border-radius: 5px;
          background: none;
          color: #6b7280;
          cursor: pointer;
          font-size: 0.85rem;
          transition: all 0.15s;
        }

        .cb-drawer-close:hover {
          background: #f3f4f6;
          color: #111827;
        }

        .cb-drawer-body {
          flex: 1;
          overflow-y: auto;
          padding: 1.25rem;
          display: flex;
          flex-direction: column;
          gap: 1.25rem;
        }

        .cb-drawer-field {
          display: flex;
          flex-direction: column;
          gap: 0.4rem;
        }

        .cb-select--full {
          min-width: unset;
          width: 100%;
        }

        .cb-drawer-footer {
          padding: 1rem 1.25rem;
          border-top: 1px solid #e5e7eb;
          flex-shrink: 0;
        }

        .cb-reset-btn--full {
          width: 100%;
          justify-content: center;
        }

        .cb-select {
          height: 2.1rem;
          padding: 0 0.75rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          font-size: 0.85rem;
          color: #1f2937;
          background: white;
          cursor: pointer;
          transition: border-color 0.15s;
          outline: none;
          min-width: 9rem;
        }

        .cb-select:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
        }

        .cb-search-wrapper {
          position: relative;
          display: flex;
          align-items: center;
        }

        .cb-search-icon {
          position: absolute;
          left: 0.65rem;
          color: #9ca3af;
          font-size: 0.8rem;
          pointer-events: none;
        }

        .cb-search-input {
          height: 2.1rem;
          padding: 0 2rem 0 2rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          font-size: 0.85rem;
          color: #1f2937;
          background: white;
          width: 100%;
          transition: border-color 0.15s;
          outline: none;
        }

        .cb-search-input:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
        }

        .cb-search-input::placeholder {
          color: #9ca3af;
        }

        .cb-search-clear {
          position: absolute;
          right: 0.5rem;
          background: none;
          border: none;
          color: #9ca3af;
          cursor: pointer;
          padding: 0.2rem;
          border-radius: 4px;
          font-size: 0.75rem;
          line-height: 1;
        }

        .cb-search-clear:hover {
          color: #6b7280;
          background: #f3f4f6;
        }

        .cb-date-range {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .cb-date-field {
          display: flex;
          align-items: center;
          gap: 0.4rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          background: white;
          padding: 0 0.5rem;
          height: 2.1rem;
          transition: border-color 0.15s;
        }

        .cb-date-field:focus-within {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
        }

        .cb-date-prefix {
          font-size: 0.72rem;
          font-weight: 600;
          color: #9ca3af;
          text-transform: uppercase;
          letter-spacing: 0.04em;
          white-space: nowrap;
          flex-shrink: 0;
        }

        .cb-date-input {
          border: none;
          outline: none;
          font-size: 0.83rem;
          color: #1f2937;
          background: transparent;
          height: 100%;
          min-width: 7rem;
          color-scheme: light;
        }

        .cb-date-sep {
          color: #d1d5db;
          font-size: 0.9rem;
          flex-shrink: 0;
        }

        .cb-reset-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          height: 2.1rem;
          padding: 0 0.85rem;
          border: 1px solid #fca5a5;
          border-radius: 6px;
          background: #fff5f5;
          color: #dc2626;
          font-size: 0.82rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }

        .cb-reset-btn:hover {
          background: #fee2e2;
          border-color: #f87171;
        }

        /* ── Table content wrapper ── */
        .cb-table-content {
          padding: 0 1rem 1rem !important;
        }

        .cb-table-content :global(.vulnerability-table-container) {
          max-height: min(74vh, 860px);
          margin-top: 0.35rem;
        }

        /* ── Table enhancements ── */
        .cb-table th.cb-th-actions {
          text-align: center;
        }

        .cb-table td {
          vertical-align: middle !important;
        }

        /* Identity cell */
        .cb-identity {
          display: flex;
          flex-direction: column;
          gap: 0.2rem;
        }

        .cb-email {
          font-weight: 600;
          color: #1f2937;
          font-size: 0.875rem;
          word-break: break-all;
        }

        .cb-username {
          font-size: 0.78rem;
          color: #6b7280;
        }

        .cb-domain-tag {
          display: inline-flex;
          align-items: center;
          font-size: 0.7rem;
          background: #eff6ff;
          color: #2563eb;
          padding: 0.1rem 0.4rem;
          border-radius: 4px;
          font-weight: 500;
          width: fit-content;
        }

        .cb-ignored-inline {
          display: inline-flex;
          align-items: center;
          gap: 0.28rem;
          font-size: 0.65rem;
          font-weight: 600;
          color: #92400e;
          letter-spacing: 0.02em;
          margin-top: 0.15rem;
          width: fit-content;
        }

        .cb-ignored-inline .fa-bell-slash {
          font-size: 0.58rem;
          opacity: 0.88;
        }

        /* Source cell */
        .cb-source {
          display: flex;
          flex-direction: column;
          gap: 0.2rem;
          max-width: 220px;
        }

        .cb-source-name {
          font-weight: 600;
          font-size: 0.875rem;
          color: #1f2937;
        }

        .cb-source-desc {
          font-size: 0.78rem;
          color: #9ca3af;
          line-height: 1.4;
          word-break: break-word;
        }

        /* Date cell */
        .cb-date {
          font-size: 0.83rem;
          color: #374151;
          font-variant-numeric: tabular-nums;
          white-space: nowrap;
        }

        .cb-muted {
          color: #d1d5db;
        }

        /* View button */
        .cb-view-btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.35rem;
          padding: 0.35rem 0.75rem;
          border: 1px solid #e5e7eb;
          border-radius: 6px;
          background: white;
          color: #374151;
          font-size: 0.78rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }

        .cb-view-btn:hover {
          background: #f3f4f6;
          border-color: #3b82f6;
          color: #2563eb;
        }

        /* ── Badges ── */
        .cb-badge {
          display: inline-flex;
          align-items: center;
          gap: 0.3rem;
          font-size: 0.72rem;
          font-weight: 600;
          padding: 0.2rem 0.55rem;
          border-radius: 99px;
          white-space: nowrap;
          text-transform: capitalize;
        }

        .cb-badge--type {
          background: #ede9fe;
          color: #5b21b6;
        }

        .cb-badge--neutral {
          background: #f3f4f6;
          color: #374151;
        }

        .cb-badge--danger {
          background: #fee2e2;
          color: #b91c1c;
        }

        .cb-badge--safe {
          background: #d1fae5;
          color: #065f46;
        }

        .cb-badge--slack-ignore {
          background: #fef3c7;
          color: #92400e;
          text-transform: none;
          font-weight: 600;
        }

        .badge-confidence-high {
          background: #fee2e2;
          color: #b91c1c;
        }

        .badge-confidence-medium {
          background: #fef3c7;
          color: #92400e;
        }

        .badge-confidence-low {
          background: #d1fae5;
          color: #065f46;
        }

        .badge-confidence-default {
          background: #f3f4f6;
          color: #374151;
        }

        /* ── Empty state ── */
        .cb-empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 0.75rem;
          padding: 3.5rem 2rem;
          color: #6b7280;
          text-align: center;
        }

        .cb-empty-icon {
          width: 3.5rem;
          height: 3.5rem;
          border-radius: 50%;
          background: #f3f4f6;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.4rem;
          color: #9ca3af;
        }

        .cb-empty-text {
          margin: 0;
          font-size: 0.9rem;
        }

        /* ── Detail Modal (table View — keep separate from query modal) ── */
        .cb-detail-modal {
          max-width: 900px !important;
          width: min(900px, 92vw) !important;
          max-height: 90vh !important;
          overflow: hidden !important;
          display: block !important;
        }

        .cb-detail-modal :global(.modal-header) {
          text-align: left;
        }

        .cb-detail-modal :global(.modal-header h2) {
          text-align: left;
        }

        .cb-modal-body {
          max-height: 70vh;
          overflow-y: auto;
          overflow-x: hidden;
          padding: 1.5rem;
          text-align: left;
        }

        .cb-modal-banner {
          display: flex;
          align-items: center;
          gap: 1rem;
          padding: 1.25rem 1.5rem;
          background: linear-gradient(135deg, #2b2c31 0%, #414652 100%);
          border-radius: 10px;
          margin-bottom: 1.5rem;
          border-left: 4px solid var(--coral, #FF444F);
        }

        .cb-modal-avatar {
          width: 3rem;
          height: 3rem;
          border-radius: 50%;
          background: rgba(255, 68, 79, 0.2);
          border: 1px solid rgba(255, 68, 79, 0.35);
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.25rem;
          color: var(--coral, #FF444F);
          flex-shrink: 0;
        }

        .cb-modal-identity {
          flex: 1;
          min-width: 0;
        }

        .cb-modal-email {
          font-weight: 700;
          font-size: 1rem;
          color: #ffffff;
          margin: 0 0 0.4rem 0;
          word-break: break-all;
        }

        .cb-modal-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 0.4rem;
          align-items: center;
        }

        .cb-modal-tag {
          display: inline-flex;
          align-items: center;
          gap: 0.3rem;
          font-size: 0.72rem;
          font-weight: 600;
          background: rgba(255,255,255,0.12);
          color: #e5e7eb;
          padding: 0.2rem 0.55rem;
          border-radius: 99px;
          border: 1px solid rgba(255,255,255,0.15);
        }

        .cb-modal-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1rem;
        }

        .cb-modal-section {
          background: #f9fafb;
          border: 1px solid #e5e7eb;
          border-radius: 8px;
          padding: 1.25rem;
        }

        .cb-modal-section--full {
          grid-column: 1 / -1;
        }

        .cb-modal-section--recommendations {
          background: #f0fdf4;
          border-color: #bbf7d0;
        }

        .cb-modal-section-title {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-size: 0.82rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: #374151;
          margin: 0 0 0.875rem 0;
        }

        .cb-modal-section-title i {
          color: var(--coral, #FF444F);
        }

        .cb-modal-section--recommendations .cb-modal-section-title i {
          color: #059669;
        }

        .cb-detail-list {
          display: flex;
          flex-direction: column;
          gap: 0.6rem;
          margin: 0;
        }

        .cb-detail-row {
          display: grid;
          grid-template-columns: max-content minmax(0, 1fr);
          column-gap: 0.75rem;
          align-items: center;
        }

        .cb-detail-row dt {
          font-size: 0.78rem;
          font-weight: 600;
          color: #9ca3af;
          text-align: right;
          min-width: 0;
          align-self: center;
        }

        .cb-detail-row dd {
          font-size: 0.875rem;
          color: #1f2937;
          margin: 0;
          min-width: 0;
          word-break: break-word;
        }

        .cb-password-plain-cell {
          width: 100%;
        }

        .cb-password-plain-wrap,
        .cb-password-plain-row {
          display: inline-flex;
          align-items: center;
          gap: 0.35rem;
          flex-wrap: wrap;
          max-width: 100%;
        }

        .cb-password-plain-row {
          margin: 0;
        }

        .cb-password-plain {
          font-size: 0.82rem;
          padding: 0.25rem 0.45rem;
          border-radius: 6px;
          background: rgba(239, 68, 68, 0.08);
          word-break: break-all;
          flex: 1;
          min-width: 0;
        }

        .cb-password-reveal-btn {
          flex-shrink: 0;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 2rem;
          height: 2rem;
          padding: 0;
          margin: 0;
          border: 1px solid #e5e7eb;
          border-radius: 8px;
          background: #fff;
          color: #4b5563;
          cursor: pointer;
          transition: background 0.15s, border-color 0.15s, color 0.15s;
        }

        .cb-password-reveal-btn:hover {
          background: #f9fafb;
          border-color: #d1d5db;
          color: #111827;
        }

        .cb-password-reveal-btn:focus-visible {
          outline: 2px solid #FF444F;
          outline-offset: 2px;
        }

        .cb-prose {
          font-size: 0.875rem;
          color: #374151;
          line-height: 1.65;
          white-space: pre-wrap;
          word-break: break-word;
          margin: 0;
        }

        .cb-link {
          color: #2563eb;
          font-size: 0.875rem;
          text-decoration: none;
          word-break: break-all;
        }

        .cb-link:hover {
          text-decoration: underline;
        }

        /* ── Query Modal (interactive search only — not table detail) ── */
        .cb-query-modal {
          width: min(920px, 96vw) !important;
          max-width: min(920px, 96vw) !important;
          max-height: 92vh;
          display: flex;
          flex-direction: column;
          overflow: hidden;
        }

        .cb-query-modal :global(.modal-header) {
          flex-shrink: 0;
          text-align: left;
        }

        .cb-query-modal-body {
          flex: 1;
          min-height: 0;
          overflow-y: auto;
          overflow-x: hidden;
          padding: 1.5rem;
          text-align: left;
        }

        .cb-query-type-picker {
          display: flex;
          flex-direction: column;
          gap: 1.25rem;
        }

        .cb-query-hint {
          margin: 0;
          color: #6b7280;
          font-size: 0.82rem;
          text-align: center;
        }

        .cb-query-type-grid {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 0.75rem;
        }

        .cb-query-type-card {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 0.65rem;
          padding: 1.5rem 1rem;
          border: 2px solid #e5e7eb;
          border-radius: 12px;
          background: white;
          cursor: pointer;
          transition: all 0.18s;
          text-align: center;
        }

        .cb-query-type-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(0,0,0,0.1);
        }

        .cb-query-type-card--domain:hover {
          border-color: var(--coral, #FF444F);
          background: #fff5f5;
        }

        .cb-query-type-card--email:hover {
          border-color: var(--coral, #FF444F);
          background: #fff5f5;
        }

        .cb-query-type-icon-wrap {
          width: 3rem;
          height: 3rem;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.2rem;
          transition: background 0.18s;
        }

        .cb-query-type-icon-wrap--domain {
          background: #ffe4e6;
          color: var(--coral, #FF444F);
        }

        .cb-query-type-card--domain:hover .cb-query-type-icon-wrap--domain {
          background: var(--coral, #FF444F);
          color: white;
        }

        .cb-query-type-icon-wrap--email {
          background: #ffe4e6;
          color: var(--coral, #FF444F);
        }

        .cb-query-type-card--email:hover .cb-query-type-icon-wrap--email {
          background: var(--coral, #FF444F);
          color: white;
        }

        .cb-query-type-icon-wrap--web-address {
          background: #ffe4e6;
          color: var(--coral, #FF444F);
        }

        .cb-query-type-card--web-address:hover {
          border-color: var(--coral, #FF444F);
          background: #fff5f5;
        }

        .cb-query-type-card--web-address:hover .cb-query-type-icon-wrap--web-address {
          background: var(--coral, #FF444F);
          color: white;
        }

        .cb-query-type-label {
          font-weight: 700;
          font-size: 0.9rem;
          color: #111827;
        }

        .cb-query-type-desc {
          font-size: 0.73rem;
          color: #9ca3af;
          line-height: 1.4;
        }

        /* ── No results state ── */
        .cb-query-no-results {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 0.6rem;
          padding: 2.25rem 1.5rem;
          background: #fafafa;
          border: 1px dashed #e5e7eb;
          border-radius: 10px;
          text-align: center;
          margin-top: 0.5rem;
        }

        .cb-query-no-results-icon {
          width: 3rem;
          height: 3rem;
          border-radius: 50%;
          background: #f3f4f6;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.1rem;
          color: #9ca3af;
        }

        .cb-query-no-results-title {
          font-weight: 700;
          font-size: 0.95rem;
          color: #374151;
          margin: 0;
        }

        .cb-query-no-results-sub {
          font-size: 0.82rem;
          color: #6b7280;
          margin: 0;
          line-height: 1.5;
          max-width: 320px;
        }

        .cb-results-found-icon {
          color: #059669;
          margin-right: 0.35rem;
        }

        .cb-query-form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .cb-back-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          padding: 0.4rem 0.75rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          background: #f9fafb;
          color: #374151;
          font-size: 0.82rem;
          font-weight: 500;
          cursor: pointer;
          align-self: flex-start;
          transition: all 0.15s;
        }

        .cb-back-btn:hover {
          background: #f3f4f6;
          border-color: #9ca3af;
        }

        .cb-query-input-group {
          display: flex;
          flex-direction: column;
          gap: 0.35rem;
        }

        .cb-query-submit {
          width: 100%;
          justify-content: center;
        }

        .cb-query-results {
          margin-top: 0.5rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          max-height: min(58vh, 560px);
          overflow-y: auto;
          padding-right: 0.25rem;
        }

        .cb-query-results-count {
          font-size: 0.8rem;
          font-weight: 600;
          color: #6b7280;
          margin: 0;
          border-top: 1px solid #e5e7eb;
          padding-top: 0.75rem;
        }

        .cb-query-results-list {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .cb-query-result-card {
          border: 1px solid #e5e7eb;
          border-radius: 8px;
          padding: 0.875rem 1rem;
          background: white;
          cursor: pointer;
          transition: all 0.15s;
        }

        .cb-query-result-card:hover {
          border-color: #3b82f6;
          box-shadow: 0 2px 8px rgba(59,130,246,0.08);
        }

        .cb-query-result-card--ignored {
          background: rgba(180, 83, 9, 0.07);
          border-color: rgba(202, 138, 4, 0.5);
          box-shadow: inset 3px 0 0 #ca8a04;
        }

        .cb-query-result-card--ignored:hover {
          border-color: rgba(180, 83, 9, 0.65);
          box-shadow: inset 3px 0 0 #ca8a04, 0 2px 8px rgba(180, 83, 9, 0.12);
        }

        .cb-query-result-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 0.75rem;
        }

        .cb-query-result-email {
          font-weight: 600;
          font-size: 0.875rem;
          color: #1f2937;
          margin: 0 0 0.2rem 0;
          word-break: break-all;
        }

        .cb-query-result-meta {
          font-size: 0.78rem;
          color: #9ca3af;
          margin: 0;
        }

        .cb-query-result-badges {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          flex-shrink: 0;
        }

        .cb-chevron {
          color: #9ca3af;
          font-size: 0.75rem;
          transition: transform 0.15s;
        }

        .cb-query-result-expanded {
          margin-top: 0.875rem;
          padding-top: 0.875rem;
          border-top: 1px solid #f3f4f6;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .cb-query-expand-block {
          display: flex;
          flex-direction: column;
          gap: 0.3rem;
        }

        .cb-query-expand-label {
          font-size: 0.7rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: #9ca3af;
          margin: 0;
        }

        .cb-query-expand-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 0.35rem;
        }

        .cb-load-more {
          width: 100%;
          justify-content: center;
          margin-top: 0.25rem;
        }

        /* ── Row hover ── */
        .breach-row-clickable {
          cursor: pointer;
          transition: background-color 0.12s;
        }

        .breach-row-clickable:hover {
          background-color: #f8fafc;
        }

        .breach-row-clickable:focus-visible {
          outline: 2px solid #3b82f6;
          outline-offset: -2px;
        }

        /* ── Dark mode ── */
        :global(body.dark-mode) .cb-filter-bar {
          background: #1f2937;
          border-bottom-color: #374151;
        }

        :global(body.dark-mode) .cb-select,
        :global(body.dark-mode) .cb-search-input {
          background: #1f2937;
          border-color: #374151;
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-date-field {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-date-input {
          background: #1f2937;
          color: #f9fafb;
          color-scheme: dark;
        }

        :global(body.dark-mode) .cb-date-prefix {
          color: #6b7280;
        }

        :global(body.dark-mode) .cb-filter-label {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-filter-toggle-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-filter-toggle-btn:hover,
        :global(body.dark-mode) .cb-filter-toggle-btn--active {
          background: #1e3a5f;
          border-color: #3b82f6;
          color: #93c5fd;
        }

        :global(body.dark-mode) .cb-filter-drawer {
          background: #111827;
          border-left-color: #374151;
        }

        :global(body.dark-mode) .cb-drawer-header,
        :global(body.dark-mode) .cb-drawer-footer {
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-drawer-title {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-drawer-close {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-drawer-close:hover {
          background: #1f2937;
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-count-badge {
          background: #374151;
          border-color: #4b5563;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-ignored-indicator {
          background: #422006;
          color: #fcd34d;
          border-color: rgba(251, 191, 36, 0.35);
        }

        :global(body.dark-mode) .cb-stat-card--total {
          background: #1e3a5f;
          border-color: #1d4ed8;
        }

        :global(body.dark-mode) .cb-stat-card--emails {
          background: #064e3b;
          border-color: #059669;
        }

        :global(body.dark-mode) .cb-stat-card--sources {
          background: #451a03;
          border-color: #b45309;
        }

        :global(body.dark-mode) .cb-stat-value {
          color: #f9fafb;
        }

        :global(body.dark-mode) .breach-row-clickable:hover {
          background-color: #1a1f2e;
        }

        /* ── Table cell text ── */
        :global(body.dark-mode) .cb-email,
        :global(body.dark-mode) .cb-source-name {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-username {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-source-desc {
          color: #6b7280;
        }

        :global(body.dark-mode) .cb-date {
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-muted {
          color: #4b5563;
        }

        /* ── Domain tag ── */
        :global(body.dark-mode) .cb-domain-tag {
          background: rgba(255, 68, 79, 0.12);
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-ignored-inline {
          color: #fcd34d;
        }

        /* ── Badges ── */
        :global(body.dark-mode) .cb-badge--type {
          background: #2e1b4e;
          color: #c4b5fd;
        }

        :global(body.dark-mode) .cb-badge--neutral {
          background: #1f2937;
          color: #9ca3af;
          border: 1px solid #374151;
        }

        :global(body.dark-mode) .cb-badge--danger {
          background: #3b0f0f;
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-badge--safe {
          background: #052e16;
          color: #86efac;
        }

        :global(body.dark-mode) .cb-badge--slack-ignore {
          background: #422006;
          color: #fcd34d;
        }

        :global(body.dark-mode) .badge-confidence-high {
          background: #3b0f0f;
          color: #fca5a5;
        }

        :global(body.dark-mode) .badge-confidence-medium {
          background: #2d1f00;
          color: #fcd34d;
        }

        :global(body.dark-mode) .badge-confidence-low {
          background: #052e16;
          color: #86efac;
        }

        :global(body.dark-mode) .badge-confidence-default {
          background: #1f2937;
          color: #9ca3af;
        }

        /* ── View button ── */
        :global(body.dark-mode) .cb-view-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-view-btn:hover {
          background: #374151;
          border-color: var(--coral, #FF444F);
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-modal-section {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-modal-section--recommendations {
          background: #064e3b;
          border-color: #059669;
        }

        :global(body.dark-mode) .cb-detail-row dd {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-password-plain {
          background: rgba(248, 113, 113, 0.12);
          color: #fecaca;
        }

        :global(body.dark-mode) .cb-password-reveal-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-password-reveal-btn:hover {
          background: #374151;
          border-color: #4b5563;
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-prose {
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-query-result-card {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-query-result-card--ignored {
          background: rgba(245, 158, 11, 0.1);
          border-color: rgba(234, 179, 8, 0.45);
          box-shadow: inset 3px 0 0 #eab308;
        }

        :global(body.dark-mode) .cb-query-result-email {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-query-type-card {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-query-type-card--domain:hover,
        :global(body.dark-mode) .cb-query-type-card--email:hover,
        :global(body.dark-mode) .cb-query-type-card--web-address:hover {
          background: #2d1515;
          border-color: var(--coral, #e8394a);
        }

        :global(body.dark-mode) .cb-query-type-label {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-query-no-results {
          background: #111827;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-query-no-results-title {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-query-no-results-sub {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-view-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-view-btn:hover {
          background: #374151;
          border-color: #3b82f6;
          color: #60a5fa;
        }

        /* ── Responsive ── */
        @media (max-width: 640px) {
          .cb-modal-grid {
            grid-template-columns: 1fr;
          }

          .cb-query-type-grid {
            grid-template-columns: 1fr;
          }

          .cb-date-range {
            flex-wrap: wrap;
          }

          .cb-stats-grid {
            grid-template-columns: 1fr;
          }
        }

        /* ── Ignore List button ── */
        .cb-ignore-btn {
          border-color: #f59e0b !important;
          color: #92400e !important;
          background: #fffbeb !important;
        }

        .cb-ignore-btn:hover {
          background: #fef3c7 !important;
          border-color: #d97706 !important;
        }

        :global(body.dark-mode) .cb-ignore-btn {
          background: #2d1f00 !important;
          border-color: #b45309 !important;
          color: #fcd34d !important;
        }

        :global(body.dark-mode) .cb-ignore-btn:hover {
          background: #3d2800 !important;
        }

        /* ── Ignore List modal ── */
        .cb-ignore-modal {
          width: min(640px, 95vw) !important;
          max-height: 90vh;
          display: flex;
          flex-direction: column;
        }

        .cb-ignore-tabs {
          display: flex;
          border-bottom: 2px solid #e5e7eb;
          background: #f9fafb;
        }

        .cb-ignore-tab {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          padding: 0.75rem 1.25rem;
          border: none;
          background: none;
          font-size: 0.875rem;
          font-weight: 500;
          color: #6b7280;
          cursor: pointer;
          border-bottom: 2px solid transparent;
          margin-bottom: -2px;
          transition: all 0.15s;
        }

        .cb-ignore-tab:hover {
          color: #111827;
          background: #f3f4f6;
        }

        .cb-ignore-tab--active {
          color: var(--coral, #FF444F);
          border-bottom-color: var(--coral, #FF444F);
          font-weight: 600;
        }

        .cb-ignore-tab-badge {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 1.35rem;
          height: 1.35rem;
          border-radius: 99px;
          background: #e5e7eb;
          color: #374151;
          font-size: 0.68rem;
          font-weight: 700;
          padding: 0 0.3rem;
        }

        .cb-ignore-tab--active .cb-ignore-tab-badge {
          background: #ffe4e6;
          color: var(--coral, #FF444F);
        }

        .cb-ignore-body {
          max-height: 60vh;
          overflow-y: auto;
          padding: 1.25rem 1.5rem !important;
        }

        /* ── List view ── */
        .cb-ignore-list {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .cb-ignore-list-hint {
          font-size: 0.8rem;
          color: #6b7280;
          background: #f0f9ff;
          border: 1px solid #bae6fd;
          border-radius: 6px;
          padding: 0.625rem 0.875rem;
          margin: 0 0 0.5rem 0;
          line-height: 1.5;
          display: flex;
          gap: 0.5rem;
          align-items: flex-start;
        }

        .cb-ignore-list-hint i {
          color: #0284c7;
          margin-top: 0.1rem;
          flex-shrink: 0;
        }

        .cb-ignore-entry {
          border: 1px solid #e5e7eb;
          border-radius: 8px;
          padding: 0.875rem 1rem;
          background: white;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .cb-ignore-entry-top {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 0.75rem;
        }

        .cb-ignore-entry-info {
          display: flex;
          flex-direction: column;
          gap: 0.2rem;
          min-width: 0;
        }

        .cb-ignore-email {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          font-weight: 600;
          font-size: 0.875rem;
          color: #1f2937;
          word-break: break-all;
        }

        .cb-ignore-email i {
          color: #6b7280;
          flex-shrink: 0;
          font-size: 0.78rem;
        }

        .cb-ignore-notes {
          font-size: 0.78rem;
          color: #6b7280;
          font-style: italic;
        }

        .cb-ignore-meta {
          font-size: 0.72rem;
          color: #9ca3af;
        }

        .cb-ignore-entry-actions {
          display: flex;
          align-items: center;
          gap: 0.35rem;
          flex-shrink: 0;
        }

        .cb-ignore-delete-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.3rem;
          padding: 0.3rem 0.6rem;
          border: 1px solid #fca5a5;
          border-radius: 5px;
          background: #fff5f5;
          color: #dc2626;
          font-size: 0.75rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }

        .cb-ignore-delete-btn:hover {
          background: #fee2e2;
        }

        .cb-ignore-delete-btn--confirm {
          background: #dc2626;
          color: white;
          border-color: #b91c1c;
        }

        .cb-ignore-cancel-btn {
          display: inline-flex;
          align-items: center;
          padding: 0.3rem 0.6rem;
          border: 1px solid #d1d5db;
          border-radius: 5px;
          background: #f9fafb;
          color: #374151;
          font-size: 0.75rem;
          cursor: pointer;
          transition: all 0.15s;
        }

        .cb-ignore-cancel-btn:hover {
          background: #f3f4f6;
        }

        .cb-ignore-scope {
          margin-top: 0.1rem;
        }

        .cb-ignore-scope-all {
          display: inline-flex;
          align-items: center;
          gap: 0.35rem;
          font-size: 0.75rem;
          font-weight: 600;
          color: #dc2626;
          background: #fee2e2;
          padding: 0.2rem 0.6rem;
          border-radius: 99px;
        }

        .cb-ignore-incidents {
          display: flex;
          flex-wrap: wrap;
          gap: 0.35rem;
        }

        .cb-ignore-incident-tag {
          font-size: 0.72rem;
          font-weight: 500;
          background: #f3f4f6;
          color: #374151;
          padding: 0.15rem 0.5rem;
          border-radius: 99px;
          border: 1px solid #e5e7eb;
        }

        .cb-ignore-password-tag {
          background: #fef3c7;
          color: #92400e;
          border-color: #fde68a;
        }

        .cb-ignore-password-group {
          margin-bottom: 0.5rem;
        }

        .cb-ignore-password-group-label {
          font-size: 0.72rem;
          color: #6b7280;
          margin: 0 0 0.25rem 0;
          display: flex;
          align-items: center;
          gap: 0.35rem;
        }

        .cb-ignore-password-mono {
          font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, monospace;
          letter-spacing: 0.04em;
        }

        /* ── Add view ── */
        .cb-ignore-add-form {
          display: flex;
          flex-direction: column;
          gap: 1.25rem;
        }

        .cb-ignore-field {
          display: flex;
          flex-direction: column;
          gap: 0.4rem;
        }

        .cb-ignore-input {
          width: 100% !important;
        }

        .cb-ignore-field-hint {
          font-size: 0.76rem;
          color: #9ca3af;
          margin: 0;
          line-height: 1.45;
        }

        .cb-ignore-required {
          color: #dc2626;
          margin-left: 0.2rem;
        }

        .cb-ignore-optional {
          font-size: 0.72rem;
          font-weight: 400;
          color: #9ca3af;
          margin-left: 0.35rem;
          text-transform: none;
          letter-spacing: 0;
        }

        .cb-ignore-incidents-loading {
          font-size: 0.82rem;
          color: #9ca3af;
          padding: 0.5rem 0;
          display: flex;
          align-items: center;
          gap: 0.4rem;
        }

        .cb-ignore-incident-search {
          margin-bottom: 0.5rem;
        }

        .cb-ignore-selected-summary {
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-size: 0.78rem;
          color: #374151;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: 5px;
          padding: 0.3rem 0.65rem;
          margin-bottom: 0.35rem;
        }

        .cb-ignore-selected-count {
          font-weight: 600;
          color: #1d4ed8;
        }

        .cb-ignore-clear-selection {
          background: none;
          border: none;
          color: #2563eb;
          font-size: 0.75rem;
          cursor: pointer;
          padding: 0;
          text-decoration: underline;
        }

        .cb-ignore-incident-list {
          max-height: 200px;
          overflow-y: auto;
          border: 1px solid #e5e7eb;
          border-radius: 7px;
          background: white;
          display: flex;
          flex-direction: column;
        }

        .cb-ignore-incident-item {
          display: flex;
          align-items: center;
          gap: 0.6rem;
          padding: 0.5rem 0.75rem;
          cursor: pointer;
          transition: background 0.12s;
          border-bottom: 1px solid #f3f4f6;
        }

        .cb-ignore-incident-item:last-child {
          border-bottom: none;
        }

        .cb-ignore-incident-item:hover {
          background: #f9fafb;
        }

        .cb-ignore-incident-item--checked {
          background: #eff6ff;
        }

        .cb-ignore-checkbox {
          width: 1rem;
          height: 1rem;
          cursor: pointer;
          flex-shrink: 0;
          accent-color: var(--coral, #FF444F);
        }

        .cb-ignore-incident-name {
          font-size: 0.82rem;
          color: #1f2937;
          line-height: 1.35;
        }

        .cb-ignore-incident-item--checked .cb-ignore-incident-name {
          font-weight: 600;
          color: #1d4ed8;
        }

        .cb-ignore-scope-notice {
          display: flex;
          align-items: flex-start;
          gap: 0.6rem;
          padding: 0.75rem 1rem;
          border-radius: 7px;
          font-size: 0.82rem;
          line-height: 1.5;
        }

        .cb-ignore-scope-notice i {
          flex-shrink: 0;
          margin-top: 0.15rem;
        }

        .cb-ignore-scope-notice--all {
          background: #fef2f2;
          border: 1px solid #fecaca;
          color: #991b1b;
        }

        .cb-ignore-scope-notice--partial {
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          color: #1e40af;
        }

        .cb-ignore-submit {
          width: 100%;
          justify-content: center;
        }

        /* ── Inline messages ── */
        .cb-ignore-error {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.65rem 0.875rem;
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 6px;
          color: #b91c1c;
          font-size: 0.82rem;
        }

        .cb-ignore-success {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.65rem 0.875rem;
          background: #f0fdf4;
          border: 1px solid #bbf7d0;
          border-radius: 6px;
          color: #15803d;
          font-size: 0.82rem;
          font-weight: 600;
        }

        /* ── Dark mode for ignore list ── */
        :global(body.dark-mode) .cb-ignore-tabs {
          background: #111827;
          border-bottom-color: #374151;
        }

        :global(body.dark-mode) .cb-ignore-tab {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-ignore-tab:hover {
          color: #f9fafb;
          background: #1f2937;
        }

        :global(body.dark-mode) .cb-ignore-entry {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-ignore-email {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-ignore-incident-tag {
          background: #374151;
          color: #d1d5db;
          border-color: #4b5563;
        }

        :global(body.dark-mode) .cb-ignore-password-tag {
          background: #451a03;
          color: #fcd34d;
          border-color: #78350f;
        }

        :global(body.dark-mode) .cb-ignore-password-group-label {
          color: #9ca3af;
        }

        :global(body.dark-mode) .cb-ignore-incident-list {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-ignore-incident-item {
          border-bottom-color: #374151;
        }

        :global(body.dark-mode) .cb-ignore-incident-item:hover {
          background: #111827;
        }

        :global(body.dark-mode) .cb-ignore-incident-item--checked {
          background: #1e3a5f;
        }

        :global(body.dark-mode) .cb-ignore-incident-name {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-ignore-incident-item--checked .cb-ignore-incident-name {
          color: #93c5fd;
        }

        :global(body.dark-mode) .cb-ignore-list-hint {
          background: #0c2232;
          border-color: #1e4b6e;
          color: #93c5fd;
        }

        /* ── Multi-email tag input ── */
        .cb-email-tags-input {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 0.35rem;
          min-height: 2.4rem;
          padding: 0.35rem 0.6rem;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          background: white;
          cursor: text;
          transition: border-color 0.15s, box-shadow 0.15s;
        }

        .cb-email-tags-input:focus-within {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
        }

        .cb-email-tag {
          display: inline-flex;
          align-items: center;
          gap: 0.3rem;
          background: #eff6ff;
          color: #1d4ed8;
          border: 1px solid #bfdbfe;
          border-radius: 99px;
          padding: 0.15rem 0.5rem 0.15rem 0.65rem;
          font-size: 0.78rem;
          font-weight: 500;
          white-space: nowrap;
          max-width: 100%;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .cb-password-tag {
          background: #fef3c7;
          color: #92400e;
          border-color: #fde68a;
        }

        .cb-email-tag-remove {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 1rem;
          height: 1rem;
          border: none;
          background: none;
          color: #60a5fa;
          cursor: pointer;
          padding: 0;
          border-radius: 50%;
          font-size: 0.6rem;
          flex-shrink: 0;
          transition: background 0.1s, color 0.1s;
        }

        .cb-email-tag-remove:hover {
          background: #bfdbfe;
          color: #1d4ed8;
        }

        .cb-email-tags-field {
          flex: 1 1 140px;
          min-width: 120px;
          border: none;
          outline: none;
          background: transparent;
          font-size: 0.85rem;
          color: #1f2937;
          padding: 0.1rem 0;
          line-height: 1.4;
        }

        .cb-email-tags-field::placeholder {
          color: #9ca3af;
        }

        .cb-ignore-field-hint kbd {
          display: inline-block;
          padding: 0.05rem 0.35rem;
          background: #f3f4f6;
          border: 1px solid #d1d5db;
          border-radius: 4px;
          font-size: 0.7rem;
          font-family: inherit;
          color: #374151;
        }

        :global(body.dark-mode) .cb-email-tags-input {
          background: #1f2937;
          border-color: #374151;
        }

        :global(body.dark-mode) .cb-email-tags-input:focus-within {
          border-color: #3b82f6;
        }

        :global(body.dark-mode) .cb-email-tag {
          background: #1e3a5f;
          color: #93c5fd;
          border-color: #1d4ed8;
        }

        :global(body.dark-mode) .cb-password-tag {
          background: #451a03;
          color: #fcd34d;
          border-color: #78350f;
        }

        :global(body.dark-mode) .cb-email-tag-remove {
          color: #60a5fa;
        }

        :global(body.dark-mode) .cb-email-tag-remove:hover {
          background: #1d4ed8;
          color: white;
        }

        :global(body.dark-mode) .cb-email-tags-field {
          color: #f9fafb;
        }

        :global(body.dark-mode) .cb-ignore-field-hint kbd {
          background: #374151;
          border-color: #4b5563;
          color: #d1d5db;
        }

        /* ── Dark mode – missing rules ── */

        /* Filter bar tag */
        :global(body.dark-mode) .cb-filter-tag {
          background: #1e3a5f;
          color: #93c5fd;
        }

        /* Reset / clear filter button */
        :global(body.dark-mode) .cb-reset-btn {
          background: #1a0a0a;
          border-color: #7f1d1d;
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-reset-btn:hover {
          background: #3b0f0f;
          border-color: #dc2626;
        }

        /* Search clear × button */
        :global(body.dark-mode) .cb-search-clear {
          color: #6b7280;
        }

        :global(body.dark-mode) .cb-search-clear:hover {
          background: #374151;
          color: #d1d5db;
        }

        /* Stat card icons */
        :global(body.dark-mode) .cb-stat-card--total .cb-stat-icon {
          background: #1e3a5f;
          color: #93c5fd;
        }

        :global(body.dark-mode) .cb-stat-card--emails .cb-stat-icon {
          background: #052e16;
          color: #86efac;
        }

        :global(body.dark-mode) .cb-stat-card--sources .cb-stat-icon {
          background: #2d1f00;
          color: #fcd34d;
        }

        :global(body.dark-mode) .cb-stat-label {
          color: #9ca3af;
        }

        /* Empty state icon */
        :global(body.dark-mode) .cb-empty-icon {
          background: #1f2937;
          color: #6b7280;
        }

        /* Table row hover */
        :global(body.dark-mode) .breach-row-clickable:focus-visible {
          outline-color: #3b82f6;
        }

        /* Modal section title */
        :global(body.dark-mode) .cb-modal-section-title {
          color: #e5e7eb;
        }

        /* Detail row dt */
        :global(body.dark-mode) .cb-detail-row dt {
          color: #6b7280;
        }

        /* Prose text */
        :global(body.dark-mode) .cb-link {
          color: #60a5fa;
        }

        /* Query results divider */
        :global(body.dark-mode) .cb-query-results-count {
          color: #9ca3af;
          border-top-color: #374151;
        }

        :global(body.dark-mode) .cb-query-result-expanded {
          border-top-color: #374151;
        }

        :global(body.dark-mode) .cb-query-result-meta {
          color: #6b7280;
        }

        /* Back button in query form */
        :global(body.dark-mode) .cb-back-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-back-btn:hover {
          background: #374151;
          border-color: #4b5563;
        }

        /* Ignore list – "All leaks suppressed" scope badge */
        :global(body.dark-mode) .cb-ignore-scope-all {
          background: #3b0f0f;
          color: #fca5a5;
        }

        /* Ignore list – scope notice banners */
        :global(body.dark-mode) .cb-ignore-scope-notice--all {
          background: #1f0a0a;
          border-color: #7f1d1d;
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-ignore-scope-notice--all strong {
          color: #f87171;
        }

        :global(body.dark-mode) .cb-ignore-scope-notice--partial {
          background: #0c1c38;
          border-color: #1e3a5f;
          color: #93c5fd;
        }

        :global(body.dark-mode) .cb-ignore-scope-notice--partial strong {
          color: #60a5fa;
        }

        /* Ignore list – delete / cancel buttons */
        :global(body.dark-mode) .cb-ignore-delete-btn {
          background: #1a0a0a;
          border-color: #7f1d1d;
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-ignore-delete-btn:hover {
          background: #3b0f0f;
        }

        :global(body.dark-mode) .cb-ignore-delete-btn--confirm {
          background: #b91c1c;
          border-color: #991b1b;
          color: #fff;
        }

        :global(body.dark-mode) .cb-ignore-cancel-btn {
          background: #1f2937;
          border-color: #374151;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-ignore-cancel-btn:hover {
          background: #374151;
        }

        /* Ignore list – selected incidents summary bar */
        :global(body.dark-mode) .cb-ignore-selected-summary {
          background: #0c1c38;
          border-color: #1e3a5f;
          color: #d1d5db;
        }

        :global(body.dark-mode) .cb-ignore-selected-count {
          color: #93c5fd;
        }

        :global(body.dark-mode) .cb-ignore-clear-selection {
          color: #60a5fa;
        }

        /* Ignore list – error / success messages */
        :global(body.dark-mode) .cb-ignore-error {
          background: #1f0a0a;
          border-color: #7f1d1d;
          color: #fca5a5;
        }

        :global(body.dark-mode) .cb-ignore-success {
          background: #052e16;
          border-color: #166534;
          color: #86efac;
        }

        /* Ignore list – notes and meta text */
        :global(body.dark-mode) .cb-ignore-notes {
          color: #6b7280;
        }

        /* Ignore list – field hints */
        :global(body.dark-mode) .cb-ignore-field-hint {
          color: #6b7280;
        }
      `}</style>
    </>
  );
};

export default BreachMonitorPanel;
