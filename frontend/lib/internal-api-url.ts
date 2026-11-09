/**
 * Server-side URL for the FastAPI backend (same rules as app/api/[...path]/route.ts).
 */
export function getInternalApiUrl(): string {
  if (process.env.NODE_ENV === 'production') {
    return process.env.INTERNAL_API_URL_PRODUCTION || 'http://backend:5005';
  }
  return process.env.INTERNAL_API_URL_DEVELOPMENT || 'http://localhost:5005';
}
