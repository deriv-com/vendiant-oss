import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json(
        { status: 401, calls_remaining: null, detail: 'Unauthorized' },
        { status: 401 },
      );
    }

    const response = await fetch(`${getInternalApiUrl()}/api/breach-monitor/quota`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
      cache: 'no-store',
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return NextResponse.json(
        { status: response.status, calls_remaining: null, detail: data.detail || data.message || 'Error' },
        { status: response.status },
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor quota API]', error);
    return NextResponse.json(
      { status: 500, calls_remaining: null, detail: 'Failed to fetch quota' },
      { status: 500 },
    );
  }
}
