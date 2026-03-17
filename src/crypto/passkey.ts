/**
 * Passkey/KYC data verification for CorePass.
 *
 * Verifies Ed448-signed data payloads from CorePass. This is NOT login —
 * it's data verification: "are these fields really signed by this CorePass user?"
 *
 * Signature input format: POST\n{path}\n{canonical JSON body}
 * Timestamp is in microseconds (Unix epoch), validated against a configurable window.
 */

import type { PasskeyData, ResolvedPasskeyConfig } from '../types.js';
import { getEd448, canonicalJson, extractPublicKeyFromHeader, hexToBytes } from './ed448.js';

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

  const diff = nowMicros > tsMicros ? nowMicros - tsMicros : tsMicros - nowMicros;
  const windowMicros = BigInt(config.timestampWindowMs) * 1000n;
  if (diff > windowMicros) {
    throw new Error('Timestamp out of range');
  }

  // 3. Extract public key (from X-Public-Key header or long-form ICAN)
  const publicKey = extractPublicKeyFromHeader(headers, coreId);

  // 4. Build canonical signature input
  //    Format: POST\n{endpoint path}\n{canonical JSON of body fields}
  //    Why this format? It binds the signature to the HTTP method + path,
  //    preventing replay attacks across different endpoints.
  const canonicalBody = canonicalJson({ coreId, credentialId, timestamp, userData });
  const signatureInput = `POST\n${config.path}\n${canonicalBody}`;

  // 5. Verify Ed448 signature
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
