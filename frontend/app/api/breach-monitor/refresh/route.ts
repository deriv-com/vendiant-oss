import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

/**
 * Proxies GET /api/breach-monitor/refresh → backend (domain sync from BREACH_MONITOR_DOMAIN_GROUPS).
 * Forwards verified user headers so require_admin can authorize.
 */
export async function GET(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const response = await fetch(`${getInternalApiUrl()}/api/breach-monitor/refresh`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: request.headers.get('authorization') || '',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
      cache: 'no-store',
      signal: AbortSignal.timeout(300000),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return NextResponse.json(
        {
          status: response.status,
          detail: (data as { detail?: string }).detail || 'Refresh failed',
          data: (data as { data?: unknown }).data,
        },
        { status: response.status }
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor refresh API]', error);
    return NextResponse.json(
      { status: 500, detail: 'Failed to refresh Breach Monitor domain data' },
      { status: 500 }
    );
  }
}
