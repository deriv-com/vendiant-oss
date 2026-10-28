import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

// Force dynamic rendering for this route
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    const identity = await getTrustedIdentity(request);
    if (!identity) {
      return NextResponse.json(
        { status: 401, description: 'Unauthorized', error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const { searchParams } = new URL(request.url);
    const qs = searchParams.toString();
    const backendEndpoint = `${getInternalApiUrl()}/api/breach-monitor${qs ? `?${qs}` : ''}`;

    console.log(`[Breach Monitor API] Fetching from: ${backendEndpoint}`);

    const response = await fetch(backendEndpoint, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: request.headers.get('authorization') || '',
        ...userIdentityProxyHeaders(identity),
        ...clientIpProxyHeaders(request),
      },
    });

    if (!response.ok) {
      console.error(`[Breach Monitor API] Backend responded with status: ${response.status}`);
      throw new Error(`Backend responded with status: ${response.status}`);
    }

    const data = await response.json();

    console.log(`[Breach Monitor API] Successfully retrieved data with ${data.data?.results?.length || 0} breaches`);

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('[Breach Monitor API] Error:', error);

    // Return error response but keep consistent format
    return NextResponse.json({
      status: 500,
      description: 'Error',
      error: error instanceof Error ? error.message : 'Unknown error',
      data: {
        results: [],
        query: {
          pagination: {
            total: 0,
            count: 0,
            page: 0
          }
        },
        next_id: ''
      }
    }, { status: 500 });
  }
}

