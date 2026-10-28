import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

/** GET /api/breach-monitor/ignore-list — fetch all entries */
export async function GET(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const response = await fetch(`${getInternalApiUrl()}/api/breach-monitor/ignore-list`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: request.headers.get('authorization') || '',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
      cache: 'no-store',
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return NextResponse.json(
        { status: response.status, detail: (data as { detail?: string }).detail || 'Failed to fetch ignore list' },
        { status: response.status }
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor ignore-list GET]', error);
    return NextResponse.json({ status: 500, detail: 'Failed to fetch ignore list' }, { status: 500 });
  }
}

/** POST /api/breach-monitor/ignore-list — add or update an entry */
export async function POST(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json().catch(() => null);
    if (!body) {
      return NextResponse.json({ status: 400, detail: 'Invalid request body' }, { status: 400 });
    }

    const response = await fetch(`${getInternalApiUrl()}/api/breach-monitor/ignore-list`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: request.headers.get('authorization') || '',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
      body: JSON.stringify(body),
      cache: 'no-store',
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return NextResponse.json(
        { status: response.status, detail: (data as { detail?: string }).detail || 'Failed to save entry' },
        { status: response.status }
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor ignore-list POST]', error);
    return NextResponse.json({ status: 500, detail: 'Failed to save ignore-list entry' }, { status: 500 });
  }
}
