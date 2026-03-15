import crypto from 'crypto';
import type { ChallengeData, ChallengeResponse, ResolvedConfig, StoreEntry } from './types.js';

/** Create a new login challenge with QR + mobile URIs */
export async function createChallenge(config: ResolvedConfig): Promise<ChallengeResponse> {
  const id = crypto.randomBytes(16).toString('hex');
  const callbackUrl = `${config.baseUrl}/auth/callback`;
  const appLinkUrl = `${config.baseUrl}/auth/app-link`;

  // Desktop (QR): type=callback — CorePass POSTs to server
  const loginUri = `corepass:login?sess=${id}&conn=${encodeURIComponent(callbackUrl)}&type=callback`;
  // Mobile (Deep Link): type=app-link — CorePass redirects via GET
  const mobileUri = `corepass:login?sess=${id}&conn=${encodeURIComponent(appLinkUrl)}&type=app-link`;

  const challenge: ChallengeData = {
    id,
    status: 'pending',
    created: Date.now(),
    ican: null,
    coreId: null,
    name: null,
    signature: null,
  };

  const entry: StoreEntry = { type: 'challenge', data: challenge, expiresAt: 0 };
  await config.store.set(`challenge:${id}`, entry, config.challengeTtl);

  const response: ChallengeResponse = {
    challengeId: id,
    loginUri,
    mobileUri,
    expiresIn: Math.floor(config.challengeTtl / 1000),
  };

  // Server-side QR generation (optional)
  if (config.generateQr) {
    try {
      const { generateQrDataUrl } = await import('./qr.js');
      response.qrDataUrl = await generateQrDataUrl(loginUri);
    } catch {
      // qrcode not installed — skip, widget generates client-side
    }
  }

  return response;
}

/** Get a challenge by ID */
export async function getChallenge(config: ResolvedConfig, challengeId: string): Promise<ChallengeData | null> {
  const entry = await config.store.get(`challenge:${challengeId}`);
  if (!entry || entry.type !== 'challenge') return null;
  return entry.data as ChallengeData;
}

/** Update a challenge (e.g. mark as authenticated) */
export async function updateChallenge(config: ResolvedConfig, challengeId: string, data: ChallengeData): Promise<void> {
  const entry: StoreEntry = { type: 'challenge', data, expiresAt: 0 };
  // Keep remaining TTL — store.set resets it, but challenge will be consumed soon
  await config.store.set(`challenge:${challengeId}`, entry, config.challengeTtl);
}

/** Delete a challenge */
export async function deleteChallenge(config: ResolvedConfig, challengeId: string): Promise<void> {
  await config.store.delete(`challenge:${challengeId}`);
}
