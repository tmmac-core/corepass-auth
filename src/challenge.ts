import crypto from 'crypto';
import type { ChallengeData, ChallengeResponse, ResolvedConfig, StoreEntry } from './types.js';

/** Create a new login challenge with QR + mobile URIs */
export async function createChallenge(config: ResolvedConfig): Promise<ChallengeResponse> {
  const id = crypto.randomBytes(16).toString('hex');
  const callbackUrl = `${config.baseUrl}/auth/callback`;

  // Note: URI path is "login/" (trailing slash) — CorePass requires this format.
  // Desktop (QR): type=callback — CorePass POSTs to server
  const loginUri = `corepass:login/?sess=${encodeURIComponent(id)}&conn=${encodeURIComponent(callbackUrl)}&type=callback`;
  // Mobile (Deep Link): also type=callback — CorePass POSTs to server, no redirect.
  // Using type=callback avoids CorePass opening its internal browser (type=app-link issue).
  // Safari keeps polling in the background → detects auth → user switches back → logged in.
  const mobileUri = `corepass:login/?sess=${encodeURIComponent(id)}&conn=${encodeURIComponent(callbackUrl)}&type=callback`;

  // App-link URI: type=app-link — CorePass redirects to conn URL with query params.
  // Alternative to callback POST. Useful when consumers build their own UI and handle
  // the redirect themselves. The /auth/app-link endpoint receives ?session=&coreID=&signature=.
  const appLinkUrl = `${config.baseUrl}/auth/app-link`;
  const appLinkUri = `corepass:login/?sess=${encodeURIComponent(id)}&conn=${encodeURIComponent(appLinkUrl)}&type=app-link`;

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
    appLinkUri,
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
