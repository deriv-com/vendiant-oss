import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import { clientIpProxyHeaders, getTrustedIdentity, userIdentityProxyHeaders } from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

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

    const response = await fetch(`${getInternalApiUrl()}/api/breach-monitor/breaches/bulk-resolve`, {
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
        { status: response.status, detail: (data as { detail?: string }).detail || 'Bulk resolve failed' },
        { status: response.status },
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor bulk-resolve POST]', error);
    return NextResponse.json({ status: 500, detail: 'Bulk resolve failed' }, { status: 500 });
  }
}
