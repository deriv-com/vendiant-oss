/**
 * Human-readable formatting for audit log rows.
 *
 * The raw rows are machine-shaped (`action: "CREATE"`, `resource_type: null`,
 * everything else buried in a `details` JSON blob), which made the list read as
 * "CREATE resource" for a large share of entries. This module turns one row into:
 *
 *   verb    – short action label for the badge ("Deleted", "Scan", "Search")
 *   tone    – colour family for the badge
 *   summary – self-contained phrase describing what was touched
 *   facts   – the handful of `details` fields worth showing without expanding
 *
 * Nothing here queries the API: existing rows benefit immediately, including the
 * legacy ones whose `resource_type` was never populated (we fall back to the
 * endpoint recorded in `details`).
 */

export type AuditTone =
  | 'create'
  | 'update'
  | 'delete'
  | 'scan'
  | 'query'
  | 'flag'
  | 'view'
  | 'neutral';

export interface AuditFact {
  label: string;
  value: string;
  /** Render in a monospace font (identifiers, domains, IPs). */
  mono?: boolean;
}

export interface AuditDescription {
  verb: string;
  tone: AuditTone;
  summary: string;
  facts: AuditFact[];
}

export interface AuditLogLike {
  action?: string;
  resource_type?: string;
  resource_id?: string;
  details?: any;
  // API-key audit rows
  key_name?: string;
  endpoint_path?: string;
  http_method?: string;
  response_code?: number;
  success?: boolean;
  request_summary?: string;
  request_data?: any;
}

const MAX_FACTS = 6;

/* ------------------------------------------------------------------ helpers */

const stripQuotes = (value: string) => value.replace(/^["'\s]+|["'\s]+$/g, '');

const clean = (value: unknown): string | null => {
  if (value === null || value === undefined) return null;
  const text = stripQuotes(String(value));
  if (!text || text.toLowerCase() === 'null' || text.toLowerCase() === 'undefined') return null;
  return text;
};

const truncate = (value: string, max: number) =>
  value.length > max ? `${value.slice(0, max - 1)}…` : value;

const titleCase = (value: string) =>
  value
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());

const sentenceCase = (value: string) =>
  value ? value.charAt(0).toUpperCase() + value.slice(1) : value;

const asList = (raw: unknown): string[] =>
  Array.isArray(raw) ? raw.map((item) => stripQuotes(String(item))).filter(Boolean) : [];

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? '' : 's'}`;

/** Long hex / numeric identifiers are noise in a summary line. */
const isOpaqueId = (segment: string) =>
  /^\d+$/.test(segment) || /^[0-9a-f]{16,}$/i.test(segment) || segment.length > 40;

/* -------------------------------------------------------------- action verbs */

const VERBS: Record<string, { verb: string; tone: AuditTone }> = {
  CREATE: { verb: 'Created', tone: 'create' },
  ADD: { verb: 'Added', tone: 'create' },
  UPDATE: { verb: 'Updated', tone: 'update' },
  DELETE: { verb: 'Deleted', tone: 'delete' },
  REMOVE: { verb: 'Removed', tone: 'delete' },
  EXCLUDE: { verb: 'Excluded', tone: 'update' },
  SCAN: { verb: 'Scan', tone: 'scan' },
  DISCOVER: { verb: 'Discovery', tone: 'scan' },
  REFRESH: { verb: 'Refreshed', tone: 'scan' },
  CHECK: { verb: 'Check', tone: 'scan' },
  EXPORT: { verb: 'Exported', tone: 'view' },
  GENERATE: { verb: 'Generated', tone: 'create' },
  VIEW: { verb: 'Viewed', tone: 'view' },
  COMPARE: { verb: 'Compared', tone: 'view' },
  REVOKED: { verb: 'Revoked', tone: 'delete' },
  ACTIVATED: { verb: 'Activated', tone: 'create' },
  'ADD VENDORS': { verb: 'Vendors added', tone: 'create' },
  'REMOVE VENDORS': { verb: 'Vendors removed', tone: 'delete' },
  'UPDATE MEMBERS': { verb: 'Updated', tone: 'update' },
  PERMISSION_ASSIGN: { verb: 'Permissions', tone: 'update' },
  PERMISSION_REVOKE: { verb: 'Permissions', tone: 'delete' },
  PERMISSION_CLEAR: { verb: 'Revoked', tone: 'delete' },
  BREACH_MONITOR_QUERY: { verb: 'Search', tone: 'query' },
  BREACH_MONITOR_EXPORT: { verb: 'Exported', tone: 'view' },
  BREACH_MONITOR_IGNORE_LIST_ADD: { verb: 'Ignored', tone: 'flag' },
  BREACH_MONITOR_IGNORE_LIST_REMOVE: { verb: 'Un-ignored', tone: 'flag' },
  BREACH_MONITOR_BREACH_RESOLVE: { verb: 'Resolved', tone: 'create' },
  BREACH_MONITOR_BREACH_UNRESOLVE: { verb: 'Reopened', tone: 'delete' },
  BREACH_MONITOR_BREACH_FALSE_POSITIVE: { verb: 'False positive', tone: 'flag' },
  BREACH_MONITOR_BREACH_FALSE_POSITIVE_REMOVE: { verb: 'FP cleared', tone: 'flag' },
};

const describeVerb = (action?: string): { verb: string; tone: AuditTone } => {
  const key = (action || '').trim().toUpperCase();
  if (!key) return { verb: 'Action', tone: 'neutral' };
  if (VERBS[key]) return VERBS[key];
  return { verb: truncate(titleCase(key), 28), tone: 'neutral' };
};

/* ------------------------------------------------------------- scan labelling */

const SCAN_LABELS: Record<string, string> = {
  vulnerability: 'Vulnerability scan',
  dns: 'DNS scan',
  email: 'Email security scan',
  network: 'Network scan',
  encryption: 'Encryption scan',
  reputation: 'Reputation scan',
  subdomain_discovery: 'Subdomain discovery',
  full_scan: 'Full scan',
  full_scan_all: 'Full scan (all vendors)',
  certifications: 'Certification check',
  breach_check: 'Breach check',
  credential_leaks: 'Credential leak scan',
};

const ACCESS_LABELS: Record<string, string> = {
  read_only: 'read-only',
  admin: 'admin',
  finegrained: 'scoped',
};

/** How much access an API key carries, in words. */
const accessLabel = (level?: string | null) => {
  if (!level) return null;
  return ACCESS_LABELS[level] || level.replace(/_/g, ' ');
};

const scanLabel = (type?: string | null) => {
  if (!type) return 'Scan';
  return SCAN_LABELS[type] || `${titleCase(type)} scan`;
};

/* -------------------------------------------------------------- fact building */

/** details keys already represented by the verb / summary line. */
const FACT_BLOCKLIST = new Set([
  'action_type',
  'context',
  'timestamp',
  'endpoint',
  'method',
  'vendor_name',
  'vendor_id',
  'scan_type',
  'queried_value',
  'query_kind',
  'permissions',
  'previous_filters',
  'incident_names',
  'user',
  'user_email',
  'email',
  'entry_id',
  'bulk',
  'breach_monitor_uids',
  'suppress_all',
  'check_all',
  'member_count',
  'members_synced',
  'action',
  'vendors_added',
  'vendors_removed',
  'manually_added',
  'permission_count',
]);

/** Preferred label + ordering for the keys we know about. */
const FACT_LABELS: Array<[string, string, boolean?]> = [
  ['domain', 'Domain', true],
  ['subdomain', 'Subdomain', true],
  ['tier', 'Tier'],
  ['industry', 'Industry'],
  ['portfolio', 'Portfolio'],
  ['api_key_name', 'Key'],
  ['scopes', 'Scopes'],
  ['scopes_added', 'Scopes granted'],
  ['scopes_removed', 'Scopes revoked'],
  ['previous_scopes', 'Previous scopes'],
  ['created_by', 'Key owner'],
  ['request_limit', 'Rate limit'],
  ['expires_in_days', 'Expires in (days)'],
  ['expires_at', 'Expires'],
  ['validity', 'Validity'],
  ['expiry_cleared_from', 'Expiry cleared'],
  ['permissions_added', 'Granted'],
  ['permissions_removed', 'Revoked'],
  ['members_added', 'Added'],
  ['members_removed', 'Removed'],
  ['permissions_granted', 'Permissions'],
  ['members_unassigned', 'Unassigned'],
  ['vendor_names', 'Vendors'],
  ['vendors_already_in_portfolio', 'Already in portfolio'],
  ['vendors_not_in_portfolio', 'Not in portfolio'],
  ['results_returned', 'Results'],
  ['matches_found', 'Matches'],
  ['row_count', 'Rows'],
  ['selected_uids_count', 'Selected'],
  ['updated_count', 'Updated'],
  ['vendors_updated', 'Vendors updated'],
  ['total_vendors', 'Vendors'],
  ['new_records', 'New records'],
  ['updated_records', 'Updated records'],
  ['password_count', 'Passwords'],
  ['breach_monitor_uid', 'Breach', true],
  ['leak_view', 'View'],
  ['include_subdomains', 'Subdomains'],
  ['auto_scan_started', 'Auto-scan'],
  ['job_id', 'Job', true],
  ['scan_job_id', 'Job', true],
  ['scan_id', 'Job', true],
];

const factValue = (key: string, raw: unknown): string | null => {
  if (raw === null || raw === undefined || raw === '') return null;
  // An unset filter ("all"/false) says nothing about what the user did.
  if (/_filter$|^search_applied$|_included$/.test(key) && (raw === 'all' || raw === false)) return null;
  // "0 vendors were already in the portfolio" is noise; a non-zero count is not.
  if (/^vendors_(already_in|not_in)_portfolio$/.test(key) && !raw) return null;
  if (typeof raw === 'boolean') {
    if (!raw) return null; // "Subdomains: no" is noise
    return key === 'auto_scan_started' ? 'started' : 'yes';
  }
  if (Array.isArray(raw)) {
    if (!raw.length) return null;
    // Chips wrap, so lists of people/permissions get room before truncating.
    return truncate(raw.map((item) => stripQuotes(String(item))).join(', '), 140);
  }
  if (typeof raw === 'object') return null; // nested blobs stay in the expanded view
  const text = clean(raw);
  if (!text) return null;
  return truncate(text, /^[0-9a-f]{16,}$/i.test(text) ? 14 : 48);
};

const buildFacts = (details: any, skip: Set<string>): AuditFact[] => {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return [];
  const facts: AuditFact[] = [];
  const used = new Set<string>();

  for (const [key, label, mono] of FACT_LABELS) {
    if (skip.has(key) || !(key in details)) continue;
    const value = factValue(key, details[key]);
    if (!value) continue;
    // job_id / scan_job_id / scan_id all map to "Job" — only keep the first.
    if (facts.some((fact) => fact.label === label)) continue;
    facts.push({ label, value, mono });
    used.add(key);
    if (facts.length >= MAX_FACTS) return facts;
  }

  // Surface unknown scalar keys too, so newly added details show up without a code change.
  for (const key of Object.keys(details)) {
    if (used.has(key) || skip.has(key) || FACT_BLOCKLIST.has(key)) continue;
    if (FACT_LABELS.some(([known]) => known === key)) continue;
    const value = factValue(key, details[key]);
    if (!value) continue;
    facts.push({ label: titleCase(key), value });
    if (facts.length >= MAX_FACTS) break;
  }

  return facts;
};

/* --------------------------------------------------- endpoint-only fallbacks */

/**
 * Rows written by the generic middleware before endpoint→resource mapping existed
 * carry nothing but `{method, endpoint}`. Turn that into something a human can read.
 */
const describeEndpoint = (
  method: string | null,
  endpoint: string | null
): { verb?: string; tone?: AuditTone; summary: string } | null => {
  if (!endpoint) return null;
  const path = endpoint.split('?')[0];

  if (path === '/api/certifications/check') {
    return { verb: 'Check', tone: 'scan', summary: 'Certification check across all vendors' };
  }
  if (path.startsWith('/api/certifications/')) {
    const domain = decodeURIComponent(path.slice('/api/certifications/'.length));
    return { summary: `Certifications for ${domain}` };
  }
  if (path === '/api/admin/permissions') {
    return { summary: 'Dashboard user permissions' };
  }
  if (path === '/api/ai-insights/generate') {
    return { verb: 'Generated', tone: 'create', summary: 'AI security insights' };
  }
  if (path === '/api/breach-monitor/query') {
    return { verb: 'Search', tone: 'query', summary: 'Breach Monitor credential-leak search' };
  }
  if (path === '/api/background-scan/start') {
    return { verb: 'Scan', tone: 'scan', summary: 'Background scan job' };
  }
  const reportMatch = path.match(/^\/api\/reports\/([^/]+)\/export-pdf$/);
  if (reportMatch) {
    return {
      verb: 'Exported',
      tone: 'view',
      summary: `PDF report for ${decodeURIComponent(reportMatch[1])}`,
    };
  }
  const fpMatch = path.match(/^\/api\/breach-monitor\/breaches\/[^/]+\/(un)?mark-false-positive$/);
  if (fpMatch) {
    return {
      verb: fpMatch[1] ? 'FP cleared' : 'False positive',
      tone: 'flag',
      summary: fpMatch[1] ? 'False positive flag cleared on breach' : 'Breach flagged as false positive',
    };
  }
  if (path === '/api/breach-monitor/breaches/bulk-resolve') {
    return { verb: 'Resolved', tone: 'create', summary: 'Bulk breach resolve' };
  }
  if (path === '/api/breach-monitor/breaches/bulk-unresolve') {
    return { verb: 'Reopened', tone: 'delete', summary: 'Bulk breach reopen' };
  }
  if (path === '/api/breach-monitor/ignore-list') {
    return { verb: 'Ignored', tone: 'flag', summary: 'Breach Monitor ignore-list entry' };
  }

  // Generic: "/api/foo/bar/123" → "Foo bar"
  const segments = path.replace(/^\/api\//, '').split('/').filter((s) => s && !isOpaqueId(s));
  if (!segments.length) return { summary: `${method || 'Request'} ${path}` };
  const resource = titleCase(segments[0]);
  const rest = segments.slice(1).map((s) => titleCase(s).toLowerCase()).join(' ');
  return { summary: rest ? `${resource} — ${rest}` : resource };
};

/* -------------------------------------------------- dashboard log description */

const describeDashboardLog = (log: AuditLogLike): AuditDescription => {
  const details = (log.details && typeof log.details === 'object' && !Array.isArray(log.details))
    ? log.details
    : {};
  const action = (log.action || '').trim().toUpperCase();
  const resourceType = clean(log.resource_type);
  const resourceId = clean(log.resource_id);
  const vendorName = clean(details.vendor_name);
  const vendorLabel = vendorName && vendorName.toLowerCase() !== 'unknown vendor' ? vendorName : null;
  const domain = clean(details.domain);
  const skip = new Set<string>(FACT_BLOCKLIST);

  let { verb, tone } = describeVerb(log.action);
  let summary: string | null = null;

  // A scan is described by what it scanned, not by the resource_type it was
  // filed under — the same resource_type (e.g. "vulnerability") is also used by
  // non-scan actions.
  const scanType = clean(details.scan_type);
  const isScanRow = ['SCAN', 'DISCOVER', 'REFRESH', 'CHECK'].includes(action) || Boolean(scanType);

  switch (isScanRow ? '__scan__' : (resourceType || '').toLowerCase()) {
    case '__scan__': {
      const target = vendorLabel || domain;
      summary = target
        ? `${scanLabel(scanType || resourceType)} for ${target}`
        : scanLabel(scanType || resourceType);
      if (target === domain) skip.add('domain');
      break;
    }

    case 'vendor':
    case 'vendors':
      summary = vendorLabel
        ? `Vendor ${vendorLabel}`
        : resourceId
          ? `Vendor #${resourceId}`
          : 'Vendor';
      break;

    case 'additional_domain':
      summary = domain
        ? `Domain ${domain}${vendorLabel ? ` on ${vendorLabel}` : ''}`
        : `Additional domain${vendorLabel ? ` on ${vendorLabel}` : ''}`;
      skip.add('domain');
      break;

    case 'subdomain': {
      const subdomain = clean(details.subdomain);
      summary = subdomain
        ? `Subdomain ${subdomain}${vendorLabel ? ` on ${vendorLabel}` : ''}`
        : `Subdomain${vendorLabel ? ` on ${vendorLabel}` : ''}`;
      skip.add('subdomain');
      break;
    }

    case 'subdomain_exclusion': {
      const subdomain = clean(details.subdomain);
      summary = subdomain
        ? `Subdomain ${subdomain} excluded from scans${vendorLabel ? ` on ${vendorLabel}` : ''}`
        : 'Subdomain exclusion';
      skip.add('subdomain');
      break;
    }

    case 'filters': {
      const actionType = clean(details.action_type);
      summary = actionType === 'clear_all_filters'
        ? 'Dashboard filters cleared'
        : 'Dashboard filters changed';
      break;
    }

    case 'api key':
    case 'api_key':
    case 'apikey': {
      const keyName = clean(details.api_key_name) || resourceId;
      const named = keyName ? `API key ${keyName}` : 'API key';
      const level = accessLabel(clean(details.access_level));
      const wasLevel = accessLabel(clean(details.access_level_was));
      const scopesAdded = asList(details.scopes_added);
      const scopesRemoved = asList(details.scopes_removed);
      const renamedFrom = clean(details.renamed_from);
      const scopeCount = typeof details.scope_count === 'number' ? details.scope_count : null;

      // How much access a key carries is the point of the row, so lead with it.
      const accessPhrase = level
        ? scopeCount !== null
          ? `${level} (${plural(scopeCount, 'scope')})`
          : level
        : null;

      if (action === 'UPDATE') {
        if (renamedFrom) {
          summary = `API key renamed: ${renamedFrom} → ${keyName}`;
        } else if (wasLevel && level) {
          summary = `${named}: ${wasLevel} → ${level} access`;
        } else if (scopesAdded.length || scopesRemoved.length) {
          const parts: string[] = [];
          if (scopesAdded.length) parts.push(`+${plural(scopesAdded.length, 'scope')}`);
          if (scopesRemoved.length) parts.push(`-${plural(scopesRemoved.length, 'scope')}`);
          summary = `${named}: ${parts.join(', ')}`;
        } else {
          summary = accessPhrase ? `${named} (${accessPhrase})` : named;
        }
      } else {
        summary = accessPhrase ? `${named} — ${accessPhrase} access` : named;
      }

      skip.add('api_key_name');
      skip.add('access_level');
      skip.add('access_level_was');
      skip.add('renamed_from');
      skip.add('scope_count');
      skip.add('credential_id');
      break;
    }

    case 'portfolio': {
      const name = resourceId || clean(details.portfolio);
      const moved = typeof details.vendors_added === 'number'
        ? details.vendors_added
        : typeof details.vendors_removed === 'number'
          ? details.vendors_removed
          : null;
      const base = name ? `Portfolio ${name}` : 'Portfolio';
      if (!name && action === 'COMPARE') {
        summary = 'Portfolio comparison';
      } else if (moved !== null) {
        summary = `${base} (${plural(moved, 'vendor')})`;
      } else if (typeof details.vendor_count === 'number') {
        summary = `${base} (${plural(details.vendor_count, 'vendor')})`;
      } else {
        summary = base;
      }
      skip.add('portfolio');
      skip.add('vendor_count');
      break;
    }

    case 'dashboard_user_permissions': {
      const target = clean(details.user) || clean(details.user_email) || resourceId;
      const granted = Array.isArray(details.permissions) ? details.permissions.length : null;
      const preset = clean(details.role_preset);
      if (action === 'PERMISSION_CLEAR') {
        summary = target ? `Dashboard access for ${target}` : 'Dashboard access';
        skip.add('role_preset');
        break;
      }
      const scope = preset
        ? `${titleCase(preset)} preset`
        : granted !== null
          ? plural(granted, 'permission')
          : 'permissions';
      summary = target ? `${sentenceCase(scope)} for ${target}` : sentenceCase(scope);
      skip.add('role_preset');
      break;
    }

    case 'access_role': {
      const roleName = clean(details.role_name) || resourceId;
      const named = roleName ? `role ${roleName}` : 'role';
      const added = asList(details.permissions_added);
      const removed = asList(details.permissions_removed);
      const membersAdded = asList(details.members_added);
      const membersRemoved = asList(details.members_removed);
      const renamedFrom = clean(details.renamed_from);

      if (action === 'DELETE') {
        const unassigned = asList(details.members_unassigned);
        summary = unassigned.length
          ? `Access ${named} (${plural(unassigned.length, 'member')} unassigned)`
          : `Access ${named}`;
      } else if (action === 'UPDATE MEMBERS') {
        // Name the people when there are few enough to read at a glance; an
        // audit row should say who was affected, not just how many.
        const touched = membersAdded.length + membersRemoved.length;
        if (touched === 0) {
          // Legacy rows recorded no member diff — don't claim nothing changed.
          summary = `Access ${named} members updated`;
        } else if (touched <= 2) {
          if (!membersRemoved.length) {
            summary = `${membersAdded.join(' and ')} added to ${named}`;
          } else if (!membersAdded.length) {
            summary = `${membersRemoved.join(' and ')} removed from ${named}`;
          } else {
            summary = `${sentenceCase(named)}: ${membersAdded[0]} added, ${membersRemoved[0]} removed`;
          }
          // Already named in the summary — a chip would just repeat it.
          skip.add('members_added');
          skip.add('members_removed');
        } else {
          const parts: string[] = [];
          if (membersAdded.length) parts.push(`${membersAdded.length} added`);
          if (membersRemoved.length) parts.push(`${membersRemoved.length} removed`);
          summary = `Access ${named} members: ${parts.join(', ')}`;
        }
      } else if (renamedFrom) {
        summary = `Access role renamed: ${renamedFrom} → ${roleName}`;
      } else if (added.length || removed.length) {
        const parts: string[] = [];
        if (added.length) parts.push(`+${plural(added.length, 'permission')}`);
        if (removed.length) parts.push(`-${plural(removed.length, 'permission')}`);
        summary = `Access ${named}: ${parts.join(', ')}`;
      } else if (action === 'CREATE') {
        const count = typeof details.permission_count === 'number' ? details.permission_count : null;
        summary = count !== null
          ? `Access ${named} with ${plural(count, 'permission')}`
          : `Access ${named}`;
      } else {
        summary = `Access ${named}`;
      }
      skip.add('role_name');
      skip.add('renamed_from');
      skip.add('permission_count');
      break;
    }

    case 'certifications': {
      const target = resourceId || domain;
      const held = asList(details.certifications_held);
      const base = target ? `Certifications for ${target}` : 'Certifications';
      summary = held.length
        ? `${base}: ${held.join(' + ')}`
        : ('certifications_held' in details ? `${base}: none` : base);
      if (target === domain) skip.add('domain');
      skip.add('certifications_held');
      skip.add('iso_27001');
      skip.add('soc2');
      break;
    }

    case 'incident': {
      const title = clean(details.title) || clean(details.incident_name) || resourceId;
      summary = title ? `Incident ${title}` : 'Security incident';
      skip.add('title');
      skip.add('incident_name');
      break;
    }

    case 'vulnerability': {
      const scope = resourceId || domain;
      if (action === 'DELETE') {
        const removed = details.duplicates_removed;
        const count = typeof removed === 'number' ? plural(removed, 'duplicate') : 'duplicates';
        summary = scope
          ? `Removed ${count} for ${scope}`
          : `Removed ${count} across all vendors`;
        if (scope === domain) skip.add('domain');
        skip.add('duplicates_removed');
      } else {
        summary = `Vulnerabilities${scope ? ` for ${scope}` : ''}`;
      }
      break;
    }

    case 'breach-monitor': {
      // Unrecognised Breach Monitor actions fall through to the endpoint fallback below,
      // which reads better than a generic "Breach Monitor credential leaks".
      const breachMonitor = describeBreachMonitor(action, details, resourceId);
      if (breachMonitor) {
        summary = breachMonitor.summary;
        if (breachMonitor.verb) verb = breachMonitor.verb;
        if (breachMonitor.tone) tone = breachMonitor.tone;
        breachMonitor.skip?.forEach((key) => skip.add(key));
      }
      break;
    }

    default: {
      if (resourceType) {
        summary = `${titleCase(resourceType)}${resourceId ? ` ${resourceId}` : ''}`;
      }
      break;
    }
  }

  if (!summary) {
    const fallback = describeEndpoint(clean(details.method), clean(details.endpoint));
    if (fallback) {
      summary = fallback.summary;
      if (fallback.verb) verb = fallback.verb;
      if (fallback.tone) tone = fallback.tone;
    }
  }

  if (!summary) {
    summary = resourceType
      ? `${titleCase(resourceType)}${resourceId ? ` ${resourceId}` : ''}`
      : 'Dashboard action';
  }

  // Vendor context is worth showing on non-vendor rows (scans, subdomains, domains).
  const facts = buildFacts(details, skip);
  if (vendorLabel && !summary.includes(vendorLabel)) {
    facts.unshift({ label: 'Vendor', value: vendorLabel });
  }

  return { verb, tone, summary, facts: facts.slice(0, MAX_FACTS) };
};

const describeBreachMonitor = (
  action: string,
  details: any,
  resourceId: string | null
): { summary: string; verb?: string; tone?: AuditTone; skip?: string[] } | null => {
  switch (action) {
    case 'BREACH_MONITOR_QUERY': {
      const value = clean(details.queried_value) || (resourceId !== 'breach_monitor_query' ? resourceId : null);
      const kind = clean(details.query_kind);
      const label = kind === 'email' ? 'email' : kind === 'domain' ? 'domain' : 'credential';
      return {
        summary: value
          ? `Breach Monitor ${label} search: ${value}`
          : 'Breach Monitor credential-leak search',
      };
    }
    case 'BREACH_MONITOR_EXPORT': {
      const view = clean(details.leak_view);
      const rows = details.row_count;
      const scope = typeof rows === 'number' ? plural(rows, 'row') : 'results';
      return {
        summary: `Exported ${scope}${view ? ` from ${view} leaks` : ' from credential leaks'}`,
        skip: ['leak_view', 'row_count'],
      };
    }
    case 'BREACH_MONITOR_IGNORE_LIST_ADD': {
      const email = clean(details.email) || resourceId;
      const incidents = Array.isArray(details.incident_names) ? details.incident_names : [];
      const scope = details.suppress_all || !incidents.length
        ? 'all incidents'
        : plural(incidents.length, 'incident');
      return { summary: `Ignore list: ${email || 'entry'} (${scope})` };
    }
    case 'BREACH_MONITOR_IGNORE_LIST_REMOVE': {
      const entry = clean(details.entry_id) || resourceId;
      return { summary: `Ignore list entry ${entry ? `#${entry}` : ''} removed`.trim() };
    }
    case 'BREACH_MONITOR_BREACH_RESOLVE':
    case 'BREACH_MONITOR_BREACH_UNRESOLVE':
    case 'BREACH_MONITOR_BREACH_FALSE_POSITIVE':
    case 'BREACH_MONITOR_BREACH_FALSE_POSITIVE_REMOVE': {
      const verbText =
        action === 'BREACH_MONITOR_BREACH_RESOLVE' ? 'resolved'
          : action === 'BREACH_MONITOR_BREACH_UNRESOLVE' ? 'reopened'
            : action === 'BREACH_MONITOR_BREACH_FALSE_POSITIVE' ? 'flagged as false positive'
              : 'cleared of the false-positive flag';
      if (details.bulk) {
        const count = details.updated_count ?? (Array.isArray(details.breach_monitor_uids) ? details.breach_monitor_uids.length : null);
        return {
          summary: `${count !== null ? plural(count, 'breach record') : 'Breach records'} ${verbText}`,
          skip: ['updated_count'],
        };
      }
      const uid = clean(details.breach_monitor_uid) || resourceId;
      return {
        summary: `Breach record ${uid ? truncate(uid, 14) : ''} ${verbText}`.replace(/\s+/g, ' ').trim(),
        skip: ['breach_monitor_uid'],
      };
    }
    default:
      return null;
  }
};

/* -------------------------------------------------------- API key log support */

const describeApiLog = (log: AuditLogLike): AuditDescription => {
  const endpoint = clean(log.endpoint_path);
  const method = clean(log.http_method);
  const derived = describeEndpoint(method, endpoint);
  const summary = clean(log.request_summary) || derived?.summary || endpoint || 'API request';

  const facts: AuditFact[] = [];
  if (endpoint) facts.push({ label: 'Endpoint', value: truncate(endpoint, 52), mono: true });
  if (log.response_code) facts.push({ label: 'Status', value: String(log.response_code) });
  if (log.key_name) facts.push({ label: 'Key', value: log.key_name });

  return {
    verb: method || 'REQUEST',
    tone: log.success === false ? 'delete' : 'view',
    summary,
    facts: facts.slice(0, MAX_FACTS),
  };
};

/* ---------------------------------------------------------------------- entry */

export const describeAuditLog = (
  log: AuditLogLike,
  logType: 'dashboard' | 'api'
): AuditDescription =>
  logType === 'api' ? describeApiLog(log) : describeDashboardLog(log);

const TONE_STYLES: Record<AuditTone, { bg: string; fg: string }> = {
  create: { bg: 'rgba(34, 197, 94, 0.14)', fg: '#15803d' },
  update: { bg: 'rgba(59, 130, 246, 0.14)', fg: '#1d4ed8' },
  delete: { bg: 'rgba(239, 68, 68, 0.14)', fg: '#b91c1c' },
  scan: { bg: 'rgba(168, 85, 247, 0.14)', fg: '#7e22ce' },
  query: { bg: 'rgba(6, 182, 212, 0.16)', fg: '#0e7490' },
  flag: { bg: 'rgba(245, 158, 11, 0.16)', fg: '#b45309' },
  view: { bg: 'rgba(100, 116, 139, 0.16)', fg: '#475569' },
  neutral: { bg: 'rgba(128, 128, 128, 0.14)', fg: '#4b5563' },
};

export const toneStyle = (tone: AuditTone) => TONE_STYLES[tone] || TONE_STYLES.neutral;
