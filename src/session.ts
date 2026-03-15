import crypto from 'crypto';
import type { SessionData, ResolvedConfig, StoreEntry } from './types.js';

/** Create an app session after successful authentication */
export async function createSession(
  config: ResolvedConfig,
  ican: string,
  coreId: string | null,
): Promise<SessionData> {
  const id = crypto.randomBytes(32).toString('hex');
  const name = config.icanNames[ican] || ican.slice(0, 10) + '...';

  const session: SessionData = {
    id,
    ican,
    name,
    coreId,
    created: Date.now(),
  };

  const entry: StoreEntry = { type: 'session', data: session, expiresAt: 0 };
  await config.store.set(`session:${id}`, entry, config.sessionTtl);

  if (config.onAuthenticated) {
    try {
      await config.onAuthenticated(session);
    } catch {
      // Don't fail auth if hook throws
    }
  }

  return session;
}

/** Validate and return session data (or null if invalid/expired) */
export async function getSession(config: ResolvedConfig, token: string): Promise<SessionData | null> {
  const entry = await config.store.get(`session:${token}`);
  if (!entry || entry.type !== 'session') return null;
  return entry.data as SessionData;
}

/** Destroy a session */
export async function destroySession(config: ResolvedConfig, token: string): Promise<void> {
  await config.store.delete(`session:${token}`);
}

/** Extract session token from request headers */
export function extractToken(req: { headers: Record<string, string | string[] | undefined> }): string | null {
  // Support both x-session-token header and Authorization: Bearer
  const headerToken = req.headers['x-session-token'];
  if (typeof headerToken === 'string' && headerToken) return headerToken;

  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    return auth.slice(7);
  }

  return null;
}
