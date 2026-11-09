import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import { clientIpProxyHeaders, getTrustedIdentity, userIdentityProxyHeaders } from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ uid: string }> }) {
  try {
    const { uid } = await params;
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const response = await fetch(
      `${getInternalApiUrl()}/api/breach-monitor/breaches/${encodeURIComponent(uid)}/mark-false-positive`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: request.headers.get('authorization') || '',
          ...userIdentityProxyHeaders(identity),
          ...clientIpProxyHeaders(request),
        },
        cache: 'no-store',
      },
    );

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return NextResponse.json(
        { status: response.status, detail: (data as { detail?: string }).detail || 'Failed to mark as false positive' },
        { status: response.status },
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor mark-false-positive PATCH]', error);
    return NextResponse.json({ status: 500, detail: 'Failed to mark as false positive' }, { status: 500 });
  }
}
