/**
 * Ed448 signature verification for CorePass.
 * Extracts the public key from a long-form ICAN and verifies
 * the signature over canonical JSON challenge data.
 *
 * Requires: @noble/curves (optional dependency)
 */

let ed448: any = null;

async function getEd448() {
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
 */
export function canonicalJson(obj: Record<string, unknown>): string {
  const sorted = Object.keys(obj).sort();
  const entries: string[] = [];
  for (const key of sorted) {
    const val = obj[key];
    if (val === undefined) continue;
    const serialized = typeof val === 'object' && val !== null
      ? canonicalJson(val as Record<string, unknown>)
      : JSON.stringify(val);
    entries.push(`${JSON.stringify(key)}:${serialized}`);
  }
  return `{${entries.join(',')}}`;
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

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
