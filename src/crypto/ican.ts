/**
 * ICAN (International Crypto Account Number) validation.
 * Format: CB + 2 check digits + 40 hex chars (BBAN) = 44 chars total.
 * Uses blockchain-wallet-validator for full validation,
 * with a fast regex pre-check fallback.
 */

const ICAN_REGEX = /^CB\d{2}[0-9A-F]{40}$/i;

/** Normalize ICAN to uppercase, trimmed */
export function normalizeIcan(ican: string): string {
  return ican.trim().toUpperCase();
}

/** Fast regex check — validates format but not checksum */
export function isValidIcanFormat(ican: string): boolean {
  return ICAN_REGEX.test(ican);
}

/**
 * Full ICAN validation using blockchain-wallet-validator.
 * Falls back to regex check if the validator isn't available.
 */
export function validateIcan(ican: string): boolean {
  const normalized = normalizeIcan(ican);
  if (!isValidIcanFormat(normalized)) return false;

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { validate } = require('blockchain-wallet-validator');
    const result = validate(normalized, 'xcb');
    return result.valid;
  } catch {
    // Validator not available — regex check passed, accept it
    return true;
  }
}

/** Check if an ICAN is in the whitelist (empty whitelist = allow all) */
export function isIcanAllowed(ican: string, allowedIcans: string[]): boolean {
  if (allowedIcans.length === 0) return true;
  const normalized = normalizeIcan(ican);
  return allowedIcans.some(allowed => normalizeIcan(allowed) === normalized);
}

/** Get display name for an ICAN */
export function getIcanName(ican: string, icanNames: Record<string, string>): string {
  const normalized = normalizeIcan(ican);
  return icanNames[normalized] || normalized.slice(0, 10) + '...';
}
