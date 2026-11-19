import { NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5005';

// Force dynamic rendering for this route
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const vendorId = searchParams.get('vendorId');

    // vendorId is user-controlled and is interpolated into a backend URL path,
    // so only accept a plain numeric id (blocks path traversal / host injection).
    if (vendorId !== null && !/^\d{1,18}$/.test(vendorId)) {
      return NextResponse.json(
        { status: 'error', message: 'Invalid vendorId', matches: [] },
        { status: 400 }
      );
    }

    // Determine which backend endpoint to call
    const backendEndpoint = vendorId
      ? `${BACKEND_URL}/api/breaches/matches/${encodeURIComponent(vendorId)}`
      : `${BACKEND_URL}/api/breaches/check`;
    
    const response = await fetch(backendEndpoint, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
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