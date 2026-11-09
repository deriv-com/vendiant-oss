/**
 * Mock auth is strictly for local development: it signs every request in as
 * an admin without an SSO gateway. It is ignored in production builds,
 * whenever an SSO JWKS URL is configured, and whenever the app's public base
 * URL points anywhere other than this machine (VND-010), so a stray
 * ENABLE_MOCK_AUTH=true or mis-set NODE_ENV on a reachable deployment cannot
 * bypass SSO.
 */
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function baseUrlIsLocal(): boolean {
  // Unset falls back to the localhost defaults used by docker-compose.
  const raw = process.env.NEXT_PUBLIC_BASE_URL;
  if (!raw) return true;
  try {
    return LOCAL_HOSTNAMES.has(new URL(raw).hostname.toLowerCase());
  } catch {
    return false;
  }
}

const mockAuthRequested = process.env.ENABLE_MOCK_AUTH === 'true';

export const isMockAuthEnabled =
  mockAuthRequested &&
  process.env.NODE_ENV !== 'production' &&
  !process.env.SSO_JWKS_URL &&
  baseUrlIsLocal();

if (mockAuthRequested && !isMockAuthEnabled) {
  console.warn(
    '[auth] ENABLE_MOCK_AUTH=true was ignored: mock auth only runs in development, ' +
      'with no SSO_JWKS_URL and a localhost NEXT_PUBLIC_BASE_URL.'
  );
}
