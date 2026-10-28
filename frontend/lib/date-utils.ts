/**
 * Parse API timestamps as UTC so the browser can render each user's local timezone.
 */
export function parseUtcTimestamp(timestamp: string): Date {
  const trimmed = timestamp.trim();
  if (!trimmed) {
    return new Date(NaN);
  }

  // Already includes an explicit timezone (Z or ±HH:MM offset).
  if (/[Zz]$|[+-]\d{2}:\d{2}$/.test(trimmed)) {
    return new Date(trimmed);
  }

  // Legacy naive timestamps from TIMESTAMP WITHOUT TIME ZONE columns (stored as UTC).
  return new Date(`${trimmed}Z`);
}

export function formatLocalDateTime(timestamp: string | undefined): string {
  if (!timestamp) return 'Unknown time';

  const date = parseUtcTimestamp(timestamp);
  return Number.isNaN(date.getTime()) ? 'Invalid time' : date.toLocaleString();
}

export function formatTimeAgo(timestamp: string | undefined): string {
  if (!timestamp) return 'Unknown time';

  const now = new Date();
  const time = parseUtcTimestamp(timestamp);

  if (Number.isNaN(time.getTime())) {
    return 'Invalid time';
  }

  const diffInSeconds = Math.floor((now.getTime() - time.getTime()) / 1000);

  if (diffInSeconds < 0) {
    const absDiff = Math.abs(diffInSeconds);
    if (absDiff < 60) return `in ${absDiff}s`;
    if (absDiff < 3600) return `in ${Math.floor(absDiff / 60)}m`;
    if (absDiff < 86400) return `in ${Math.floor(absDiff / 3600)}h`;
    return `in ${Math.floor(absDiff / 86400)}d`;
  }

  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  return `${Math.floor(diffInSeconds / 86400)}d ago`;
}
