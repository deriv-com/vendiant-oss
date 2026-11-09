import { NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5005';

// Force dynamic rendering for this route
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const vendorId = searchParams.get('vendorId');
    
    // Determine which backend endpoint to call
    const backendEndpoint = vendorId 
      ? `${BACKEND_URL}/api/breaches/matches/${vendorId}`
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
      message: `Failed to check breaches: ${error instanceof Error ? error.message : 'Unknown error'}`,
      matches: []
    }, { status: 500 });
  }
} 