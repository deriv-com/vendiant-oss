import { NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5005';

// Force dynamic rendering for this route
export const dynamic = 'force-dynamic';

// Vendor ids are integers. Anything else must not be interpolated into the backend URL.
const VENDOR_ID_PATTERN = /^[1-9][0-9]{0,17}$/;

function backendEndpoint(path: string): URL | null {
  let allowed: URL;
  let endpoint: URL;
  try {
    allowed = new URL(BACKEND_URL);
    endpoint = new URL(`${BACKEND_URL}${path}`);
  } catch {
    return null;
  }
  if (allowed.protocol !== 'http:' && allowed.protocol !== 'https:') {
    return null;
  }
  if (endpoint.origin !== allowed.origin) {
    return null;
  }
  if (!endpoint.pathname.startsWith('/api/breaches/')) {
    return null;
  }
  return endpoint;
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const vendorId = searchParams.get('vendorId');

    let path = '/api/breaches/check';
    if (vendorId !== null && vendorId !== '') {
      if (!VENDOR_ID_PATTERN.test(vendorId)) {
        return NextResponse.json({
          status: 'error',
          message: 'Invalid vendorId',
          matches: []
        }, { status: 400 });
      }
      path = `/api/breaches/matches/${vendorId}`;
    }

    const endpoint = backendEndpoint(path);
    if (!endpoint) {
      return NextResponse.json({
        status: 'error',
        message: 'Backend is not configured',
        matches: []
      }, { status: 500 });
    }

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      redirect: 'error',
    });

    if (!response.ok) {
      throw new Error(`Backend responded with status: ${response.status}`);
    }

    const data = await response.json();

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('Error in breach check API:', error);

    return NextResponse.json({
      status: 'error',
      message: 'Failed to check breaches',
      matches: []
    }, { status: 500 });
  }
}
