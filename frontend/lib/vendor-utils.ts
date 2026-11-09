/**
 * Utility functions for vendor-related operations
 */

/**
 * Optional map of domain -> logo path for vendors whose logo you want to
 * ship with the dashboard (place the files in `public/`). Anything not
 * listed falls back to public favicon services.
 */
const CUSTOM_LOGOS: Record<string, string> = {
  // 'example.com': '/example_vendor.png',
};

/**
 * Get the appropriate logo URL for a vendor with multiple fallback options
 * @param domain - The vendor's domain
 * @param fallbackLogo - The fallback logo URL from the API
 * @returns The logo URL to use (primary fallback)
 */
export function getVendorLogoUrl(domain: string, fallbackLogo?: string): string {
  if (CUSTOM_LOGOS[domain]) {
    return CUSTOM_LOGOS[domain];
  }

  // If backend provided a logo, use it
  if (fallbackLogo && !fallbackLogo.includes('clearbit')) {
    return fallbackLogo;
  }

  // Use Google Favicons as primary (most reliable free service)
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=128`;
}

/**
 * Get multiple logo URL options for fallback handling
 * @param domain - The vendor's domain
 * @returns Array of logo URLs to try in order
 */
export function getVendorLogoUrls(domain: string): string[] {
  if (CUSTOM_LOGOS[domain]) {
    return [CUSTOM_LOGOS[domain]];
  }

  const urls: string[] = [];
  urls.push(`https://www.google.com/s2/favicons?domain=${domain}&sz=128`);
  urls.push(`https://icon.horse/icon/${domain}`);
  urls.push(`https://${domain}/favicon.ico`);
  urls.push(`https://www.google.com/s2/favicons?domain=${domain}&sz=64`);
  urls.push(`https://icons.duckduckgo.com/ip3/${domain}.ico`);
  return urls;
}

/**
 * Check if a vendor has a custom bundled logo
 * @param domain - The vendor's domain
 * @returns True if the vendor has a custom logo
 */
export function hasCustomLogo(domain: string): boolean {
  return domain in CUSTOM_LOGOS;
}
