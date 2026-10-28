import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

export const dynamic = 'force-dynamic';

/** GET /api/me/permissions — effective permissions for the signed-in user. */
export async function GET(request: NextRequest) {
  const identity = await getTrustedIdentity(request);
  if (!identity) {
    return NextResponse.json({ success: false, detail: 'Unauthorized' }, { status: 401 });
  }

  try {
    const response = await fetch(`${getInternalApiUrl()}/api/me/permissions`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
      cache: 'no-store',
    });

    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[me/permissions]', error);
    return NextResponse.json(
      { success: false, detail: 'Failed to load permissions' },
      { status: 500 },
    );
  }
}
