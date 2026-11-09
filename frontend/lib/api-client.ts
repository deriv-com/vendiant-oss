/**
 * API client for audit and shared fetch helpers.
 *
 * In the browser, use same-origin (empty base) so requests hit the Next.js app first.
 * Middleware adds x-user-* headers; /api/* is proxied to FastAPI (see app/api/[...path]/route.ts).
 * Do not point the browser at localhost:5005 — that bypasses middleware and /api/audit-logs/log
 * returns 400 (missing X-User-Email).
 */
function getApiBaseUrl(): string {
  if (typeof window !== 'undefined') {
    if (process.env.NEXT_PUBLIC_API_URL) {
      return process.env.NEXT_PUBLIC_API_URL;
    }
    if (process.env.NODE_ENV === 'production') {
      return '';
    }
    return '';
  }
  return (
    process.env.INTERNAL_API_URL_PRODUCTION ||
    (process.env.NODE_ENV === 'production' ? 'http://backend:5005' : 'http://localhost:5005')
  );
}

const API_BASE_URL = getApiBaseUrl();

/**
 * Core fetch wrapper. Adds Content-Type and merges any caller-supplied headers.
 * User identity headers are forwarded automatically by the Next.js rewrite layer.
 */
export async function apiRequest(
  endpoint: string,
  options: RequestInit = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  const url = endpoint.startsWith('http')
    ? endpoint
    : `${API_BASE_URL}${endpoint}`;

  try {
    return await fetch(url, { ...options, headers });
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}

export async function apiGet(
  endpoint: string,
  options: RequestInit = {},
): Promise<Response> {
  return apiRequest(endpoint, { method: 'GET', ...options });
}

export async function apiPost(
  endpoint: string,
  data?: unknown,
  options: RequestInit = {},
): Promise<Response> {
  return apiRequest(endpoint, {
    method: 'POST',
    body: data !== undefined ? JSON.stringify(data) : undefined,
    ...options,
  });
}

export async function apiPut(
  endpoint: string,
  data?: unknown,
  options: RequestInit = {},
): Promise<Response> {
  return apiRequest(endpoint, {
    method: 'PUT',
    body: data !== undefined ? JSON.stringify(data) : undefined,
    ...options,
  });
}

export async function apiDelete(
  endpoint: string,
  options: RequestInit = {},
): Promise<Response> {
  return apiRequest(endpoint, { method: 'DELETE', ...options });
}

/**
 * Log a user action manually (for frontend-only events not covered by middleware).
 */
export async function logUserAction(
  action: string,
  resourceType?: string,
  resourceId?: string,
  details?: unknown,
): Promise<boolean> {
  try {
    const response = await apiPost('/api/audit-logs/log', {
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      details,
    });
    return response.ok;
  } catch (error) {
    console.error('Failed to log user action:', error);
    return false;
  }
}
