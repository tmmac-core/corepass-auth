/**
 * Passkey/KYC data verification for CorePass.
 *
 * Verifies Ed448-signed data payloads from CorePass. This is NOT login —
 * it's data verification: "are these fields really signed by this CorePass user?"
 *
 * Signature input format: POST\n{path}\n{canonical JSON body}
 * Timestamp is in microseconds (Unix epoch), validated against a configurable window.
 */

import crypto from 'crypto';
import type { PasskeyData, ResolvedPasskeyConfig } from '../types.js';
import { getEd448, canonicalJson, extractPublicKeyFromHeader, hexToBytes } from './ed448.js';

// Replay protection: track used signature hashes so the same signed payload
// cannot be submitted twice within the timestamp window.
const usedSignatures = new Map<string, number>(); // hash → expiresAt

function checkReplay(signatureHex: string, windowMs: number): void {
  const hash = crypto.createHash('sha256').update(signatureHex).digest('hex');
  const now = Date.now();

  // Cleanup expired entries (piggyback on each call — lightweight)
  if (usedSignatures.size > 1000) {
    for (const [k, exp] of usedSignatures) {
      if (now > exp) usedSignatures.delete(k);
    }
  }

  if (usedSignatures.has(hash)) {
    throw new Error('Signature already used (replay detected)');
  }
  usedSignatures.set(hash, now + windowMs);
}

/**
 * Verify a signed passkey data payload from CorePass.
 *
 * @param body - The request body containing coreId, credentialId, timestamp, userData
 * @param signatureHex - The Ed448 signature from X-Signature header (hex-encoded)
 * @param headers - Request headers (for X-Public-Key fallback)
 * @param config - Resolved passkey configuration
 * @throws Error if verification fails (missing fields, expired timestamp, bad signature)
 */
export async function verifyPasskeyData(
  body: PasskeyData,
  signatureHex: string,
  headers: Record<string, string | string[] | undefined>,
  config: ResolvedPasskeyConfig,
): Promise<void> {
  const { coreId, credentialId, timestamp, userData } = body;

  // 1. Validate required fields
  if (!coreId || !credentialId || !timestamp) {
    throw new Error('Missing required fields: coreId, credentialId, timestamp');
  }

  if (!signatureHex) {
    throw new Error('Missing X-Signature header');
  }

  // 2. Validate timestamp (microseconds since Unix epoch)
  //    Why microseconds? CorePass uses microsecond precision internally.
  //    We convert the configured window (ms) to microseconds for comparison.
  const nowMicros = BigInt(Date.now()) * 1000n;
  let tsMicros: bigint;
  try {
    tsMicros = BigInt(timestamp);
  } catch {
    throw new Error('Invalid timestamp format');
  }

  // Only accept timestamps in the past (with small leeway for clock skew).
  // Why no future timestamps? An attacker could pre-generate signed payloads
  // with future timestamps and replay them later within the window.
  const clockSkewMicros = 30n * 1_000_000n; // 30 seconds leeway for clock differences
  if (tsMicros > nowMicros + clockSkewMicros) {
    throw new Error('Timestamp is in the future');
  }
  const windowMicros = BigInt(config.timestampWindowMs) * 1000n;
  if (nowMicros - tsMicros > windowMicros) {
    throw new Error('Timestamp out of range');
  }

  // 3. Replay protection — reject signatures that have already been used
  checkReplay(signatureHex, config.timestampWindowMs);

  // 4. Extract public key (from X-Public-Key header or long-form ICAN)
  const publicKey = extractPublicKeyFromHeader(headers, coreId);

  // 5. Build canonical signature input
  //    Format: POST\n{endpoint path}\n{canonical JSON of body fields}
  //    Why this format? It binds the signature to the HTTP method + path,
  //    preventing replay attacks across different endpoints.
  const canonicalBody = canonicalJson({ coreId, credentialId, timestamp, userData });
  const signatureInput = `POST\n${config.path}\n${canonicalBody}`;

  // 6. Verify Ed448 signature
  const curve = await getEd448();
  const msg = new TextEncoder().encode(signatureInput);
  const sigBytes = hexToBytes(signatureHex);

  let valid: boolean;
  try {
    valid = curve.verify(sigBytes, msg, publicKey);
  } catch {
    throw new Error('Signature verification failed');
  }

  if (!valid) {
    throw new Error('Invalid Ed448 signature');
  }
}
