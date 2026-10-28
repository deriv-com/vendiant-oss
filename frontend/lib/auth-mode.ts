/**
 * Mock auth is strictly for local development: it signs every request in as
 * an admin without an SSO gateway. It is ignored in production builds and
 * whenever an SSO JWKS URL is configured.
 */
export const isMockAuthEnabled =
  process.env.ENABLE_MOCK_AUTH === 'true' &&
  process.env.NODE_ENV !== 'production' &&
  !process.env.SSO_JWKS_URL;
