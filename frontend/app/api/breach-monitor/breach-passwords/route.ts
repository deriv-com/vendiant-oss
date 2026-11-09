import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

/** GET /api/breach-monitor/breach-passwords?email=... — return distinct passwords for an email */
export async function GET(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const email = request.nextUrl.searchParams.get('email') || '';
    const backendUrl = `${getInternalApiUrl()}/api/breach-monitor/breach-passwords?email=${encodeURIComponent(email)}`;

    const response = await fetch(backendUrl, {
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
        { status: response.status, detail: (data as { detail?: string }).detail || 'Failed to fetch passwords' },
        { status: response.status }
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor breach-passwords GET]', error);
    return NextResponse.json({ status: 500, detail: 'Failed to fetch passwords' }, { status: 500 });
  }
}
