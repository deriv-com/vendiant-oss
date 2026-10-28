import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

/** DELETE /api/breach-monitor/ignore-list/[id] — remove an entry */
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id: idStr } = await params;
  const id = Number(idStr);
  if (!Number.isInteger(id) || id <= 0) {
    return NextResponse.json({ status: 422, detail: 'Invalid entry id' }, { status: 422 });
  }

  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json({ status: 401, detail: 'Unauthorized' }, { status: 401 });
    }

    const response = await fetch(
      `${getInternalApiUrl()}/api/breach-monitor/ignore-list/${id}`,
      {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: request.headers.get('authorization') || '',
          ...userIdentityProxyHeaders(identity),
          ...clientIpProxyHeaders(request),
        },
        cache: 'no-store',
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return NextResponse.json(
        { status: response.status, detail: (data as { detail?: string }).detail || 'Delete failed' },
        { status: response.status }
      );
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor ignore-list DELETE]', error);
    return NextResponse.json({ status: 500, detail: 'Failed to delete entry' }, { status: 500 });
  }
}
