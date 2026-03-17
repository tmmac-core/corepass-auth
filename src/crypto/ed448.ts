/**
 * Ed448 signature verification for CorePass.
 * Extracts the public key from a long-form ICAN and verifies
 * the signature over canonical JSON challenge data.
 *
 * Requires: @noble/curves (optional dependency)
 */

let ed448: any = null;

export async function getEd448() {
  if (ed448) return ed448;
  try {
    // Must use .js extension — @noble/curves exports require it
    const mod = await import('@noble/curves/ed448.js');
    ed448 = mod.ed448;
    return ed448;
  } catch {
    throw new Error(
      'Ed448 verification requires @noble/curves. Install with: npm install @noble/curves'
    );
  }
}

/**
 * Extract the Ed448 public key from a long-form ICAN.
 * Long-form ICAN: CB + 2 check digits + 57 bytes BBAN (114 hex chars)
 * The BBAN contains the public key (57 bytes = Ed448 public key size).
 * Short-form ICAN (20 bytes BBAN) doesn't contain the full public key.
 */
export function extractPublicKey(ican: string): Uint8Array | null {
  const normalized = ican.trim().toUpperCase();
  // Long-form ICAN: 2 (CB) + 2 (check) + 114 (57 bytes hex) = 118 chars
  if (normalized.length < 118 || !normalized.startsWith('CB')) return null;

  const bban = normalized.slice(4); // Skip CB + check digits
  if (bban.length < 114) return null;

  const bytes = new Uint8Array(57);
  for (let i = 0; i < 57; i++) {
    bytes[i] = parseInt(bban.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Canonical JSON serialization for signature verification.
 * Keys sorted alphabetically, no whitespace.
 * Recursively handles nested objects AND arrays.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const sorted = Object.keys(obj).sort();
    const entries: string[] = [];
    for (const key of sorted) {
      const val = obj[key];
      if (val === undefined) continue;
      entries.push(`${JSON.stringify(key)}:${canonicalJson(val)}`);
    }
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * Verify an Ed448 signature from CorePass.
 * @param coreId - The ICAN (long-form for public key extraction)
 * @param signature - Hex-encoded Ed448 signature (114 bytes = 228 hex chars)
 * @param challengeData - The data that was signed (session + connection info)
 * @returns true if signature is valid, false otherwise
 */
export async function verifyEd448Signature(
  coreId: string,
  signature: string,
  challengeData: Record<string, unknown>,
): Promise<boolean> {
  const curve = await getEd448();

  const pubKey = extractPublicKey(coreId);
  if (!pubKey) return false;

  const message = new TextEncoder().encode(canonicalJson(challengeData));
  const sigBytes = hexToBytes(signature);
  if (sigBytes.length !== 114) return false;

  try {
    return curve.verify(sigBytes, message, pubKey);
  } catch {
    return false;
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Extract Ed448 public key from X-Public-Key header or fall back to ICAN BBAN.
 *
 * Why this exists: Short-form ICANs (20-byte BBAN) don't contain the full
 * public key. The X-Public-Key header lets CorePass pass it explicitly.
 * Long-form ICANs (57-byte BBAN) contain the key directly.
 */
export function extractPublicKeyFromHeader(
  headers: Record<string, string | string[] | undefined>,
  coreId: string,
): Uint8Array {
  const headerValue = headers['x-public-key'] || headers['X-Public-Key'];
  const val = typeof headerValue === 'string' ? headerValue.trim() : undefined;

  if (val) {
    // Try as hex (114 hex chars = 57 bytes)
    if (/^[0-9a-f]{114}$/i.test(val)) {
      return hexToBytes(val);
    }
    // Try as base64
    const buf = Buffer.from(val, 'base64');
    if (buf.length === 57) {
      return new Uint8Array(buf);
    }
    throw new Error('X-Public-Key must be 57 bytes (114 hex chars or 76 base64 chars)');
  }

  // Fall back to extracting from long-form ICAN
  const pubKey = extractPublicKey(coreId);
  if (!pubKey) {
    throw new Error(
      'Short-form ICAN cannot be used for signature verification without X-Public-Key header'
    );
  }
  return pubKey;
}
