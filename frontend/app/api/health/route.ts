import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'vendiant-frontend',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  }, { status: 200 });
} 