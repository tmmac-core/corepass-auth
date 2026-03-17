import type { Request, Response, NextFunction } from 'express';
import type { CorePassAuthConfig, CorePassAuth, ResolvedConfig, ResolvedPasskeyConfig } from './types.js';
import { MemoryStore } from './stores/memory.js';
import { createRouter } from './router.js';
import { getSession, extractToken } from './session.js';
import { normalizeIcan } from './crypto/ican.js';

// Re-export public types
export type { CorePassAuthConfig, CorePassAuth, SessionData, SessionStore, StoreEntry, PasskeyConfig, PasskeyData, PasskeyResult } from './types.js';
export { MemoryStore } from './stores/memory.js';
export { validateIcan, normalizeIcan, isIcanAllowed } from './crypto/ican.js';
export { verifyEd448Signature, extractPublicKeyFromHeader, canonicalJson } from './crypto/ed448.js';
export { verifyPasskeyData } from './crypto/passkey.js';
export { generateQrDataUrl, generateQrSvg } from './qr.js';

/**
 * Create a CorePass authentication instance.
 *
 * @example
 * ```js
 * const { corepassAuth } = require('@tmmac/corepass-auth');
 *
 * const auth = corepassAuth({
 *   baseUrl: 'https://your-app.com',
 *   allowedIcans: ['CB1234567890ABCDEF1234567890ABCDEF1234567890'],
 *   icanNames: { 'CB1234567890ABCDEF1234567890ABCDEF1234567890': 'Alice' },
 * });
 *
 * app.use('/auth', auth.router);
 * app.get('/api/data', auth.requireAuth, handler);
 * ```
 */
export function corepassAuth(userConfig: CorePassAuthConfig): CorePassAuth {
  // Resolve config with defaults
  const store = userConfig.store || new MemoryStore();
  const passkey: ResolvedPasskeyConfig = {
    enabled: userConfig.passkey?.enabled ?? false,
    path: userConfig.passkey?.path ?? '/passkey/data',
    timestampWindowMs: userConfig.passkey?.timestampWindowMs ?? 10 * 60 * 1000, // 10min
  };

  const config: ResolvedConfig = {
    baseUrl: userConfig.baseUrl.replace(/\/+$/, ''), // Strip trailing slash
    allowedIcans: (userConfig.allowedIcans || []).map(normalizeIcan),
    icanNames: normalizeIcanNames(userConfig.icanNames || {}),
    sessionTtl: userConfig.session?.ttl ?? 24 * 60 * 60 * 1000, // 24h
    challengeTtl: userConfig.session?.challengeTtl ?? 5 * 60 * 1000, // 5min
    verifySignature: userConfig.verifySignature ?? false,
    generateQr: userConfig.generateQr ?? false,
    store,
    onAuthenticated: userConfig.onAuthenticated,
    passkey,
  };

  const router = createRouter(config);

  const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({ error: 'Nicht autorisiert' });
    }

    const session = await getSession(config, token);
    if (!session) {
      return res.status(401).json({ error: 'Nicht autorisiert' });
    }

    // Attach session to request for downstream handlers
    (req as any).corepassSession = session;
    next();
  };

  const getSessionFn = async (req: Request) => {
    const token = extractToken(req);
    if (!token) return null;
    return getSession(config, token);
  };

  const destroy = () => {
    if (store instanceof MemoryStore) {
      store.destroy();
    }
  };

  return { router, requireAuth, getSession: getSessionFn, destroy };
}
/** Normalize all ICAN keys in the names map to uppercase */
function normalizeIcanNames(names: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(names)) {
    normalized[normalizeIcan(key)] = value;
  }
  return normalized;
}
