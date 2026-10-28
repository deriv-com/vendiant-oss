import { NextRequest, NextResponse } from 'next/server';
import { getInternalApiUrl } from '@/lib/internal-api-url';
import {
  getTrustedIdentity,
  userIdentityProxyHeaders,
  clientIpProxyHeaders,
} from '@/lib/trusted-request-identity';

// Force dynamic rendering for this catch-all API route
export const dynamic = 'force-dynamic';

function getApiCorsAllowOrigin(): string {
  if (process.env.CORS_ACCESS_CONTROL_ALLOW_ORIGIN) {
    return process.env.CORS_ACCESS_CONTROL_ALLOW_ORIGIN;
  }
  if (process.env.NEXT_PUBLIC_BASE_URL) {
    return process.env.NEXT_PUBLIC_BASE_URL;
  }
  return process.env.NODE_ENV === 'production'
    ? 'http://localhost:8081'
    : 'http://localhost:3005';
}

async function forwardRequest(request: NextRequest, path: string) {
  const identity = await getTrustedIdentity(request);
  if (!identity) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const internalApiUrl = getInternalApiUrl();
  const url = new URL(request.url);
  const targetUrl = `${internalApiUrl}/api/${path}${url.search}`;

  console.log(`[API Proxy] ${request.method} ${path} → ${targetUrl}`);

  try {
    let body: string | ArrayBuffer | undefined;
    const contentType = request.headers.get('content-type');

    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      if (contentType?.includes('application/json')) {
        body = await request.text();
      } else if (contentType?.includes('multipart/form-data')) {
        body = await request.arrayBuffer();
      }
    }

    const response = await fetch(targetUrl, {
      method: request.method,
      headers: {
        'Content-Type': request.headers.get('content-type') || 'application/json',
        Authorization: request.headers.get('authorization') || '',
        'User-Agent': request.headers.get('user-agent') || 'Vendiant-Frontend',
        ...clientIpProxyHeaders(request),
        ...userIdentityProxyHeaders(identity),
      },
      body,
      signal: AbortSignal.timeout(300000),
    });

    const responseContentType = response.headers.get('content-type') || '';

    // Binary/non-JSON responses (PDF exports, downloads, images, etc.) must be
    // streamed back as-is. Do NOT attempt to text()/JSON.parse() them, since a
    // valid non-JSON payload would otherwise be mistaken for a parse failure
    // and incorrectly reported as a 502.
    if (!responseContentType.includes('application/json')) {
      const arrayBuffer = await response.arrayBuffer();

      console.log(
        `[API Proxy] ${request.method} ${path} → ${response.status} (${arrayBuffer.byteLength} bytes, ${responseContentType || 'no content-type'})`,
      );

      const passthroughHeaders: Record<string, string> = {
        'Content-Type': responseContentType || 'application/octet-stream',
        'Cache-Control': response.headers.get('cache-control') || 'no-cache',
        'Access-Control-Allow-Origin': getApiCorsAllowOrigin(),
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      };
      const contentDisposition = response.headers.get('content-disposition');
      if (contentDisposition) {
        passthroughHeaders['Content-Disposition'] = contentDisposition;
      }

      return new NextResponse(arrayBuffer, {
        status: response.status,
        headers: passthroughHeaders,
      });
    }

    const responseText = await response.text();
    let responseData: unknown;
    let isJson = false;

    try {
      responseData = JSON.parse(responseText);
      isJson = true;
    } catch (parseError) {
      console.error(`[API Proxy] JSON parse error for ${path}:`, parseError);
      responseData = {
        error: 'Invalid JSON response',
        message: 'Backend returned non-JSON response',
        status_code: response.status,
      };
    }

    console.log(
      `[API Proxy] ${request.method} ${path} → ${response.status} (${responseText.length} bytes)`,
    );

    return NextResponse.json(responseData, {
      status: isJson ? response.status : 502,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': response.headers.get('cache-control') || 'no-cache',
        'Access-Control-Allow-Origin': getApiCorsAllowOrigin(),
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  } catch (error: unknown) {
    const err = error as { name?: string; code?: string; message?: string };
    console.error(
      `[API Proxy] Error forwarding ${request.method} ${path} → ${targetUrl}:`,
      err?.message || error,
    );

    if (err?.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Request timeout', message: 'The request took too long to complete' },
        { status: 408 },
      );
    }

    if (err?.code === 'ECONNREFUSED' || err?.message?.includes('fetch failed')) {
      return NextResponse.json(
        {
          error: 'Backend unavailable',
          message: 'Could not connect to backend service',
          backend: internalApiUrl,
        },
        { status: 503 },
      );
    }

    return NextResponse.json(
      { error: 'Proxy error', message: err?.message || 'An unexpected error occurred' },
      { status: 500 },
    );
  }
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const params = await context.params;
  return forwardRequest(request, params.path.join('/'));
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const params = await context.params;
  return forwardRequest(request, params.path.join('/'));
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const params = await context.params;
  return forwardRequest(request, params.path.join('/'));
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const params = await context.params;
  return forwardRequest(request, params.path.join('/'));
}

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const params = await context.params;
  return forwardRequest(request, params.path.join('/'));
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': getApiCorsAllowOrigin(),
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
      'Access-Control-Max-Age': '86400',
    },
  });
}
