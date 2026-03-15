import type { Request, Response, NextFunction, Router } from 'express';

// ===== Config =====

export interface CorePassAuthConfig {
  /** Base URL of the app (e.g. https://your-app.com) */
  baseUrl: string;

  /** Optional ICAN whitelist — empty array or omitted = allow all */
  allowedIcans?: string[];

  /** Optional ICAN → display name mapping */
  icanNames?: Record<string, string>;

  /** Session configuration */
  session?: {
    /** App session TTL in ms (default: 24h) */
    ttl?: number;
    /** Challenge TTL in ms (default: 5min) */
    challengeTtl?: number;
  };

  /** Enable Ed448 signature verification (requires @noble/curves) */
  verifySignature?: boolean;

  /** Pluggable session/challenge store (default: MemoryStore) */
  store?: SessionStore;

  /** Hook called after successful authentication */
  onAuthenticated?: (session: SessionData) => void | Promise<void>;

  /** Enable server-side QR generation (requires qrcode package) */
  generateQr?: boolean;
}

// ===== Session Store =====

export interface SessionStore {
  set(key: string, value: StoreEntry, ttlMs: number): Promise<void>;
  get(key: string): Promise<StoreEntry | null>;
  delete(key: string): Promise<void>;
  cleanup?(): Promise<void>;
}

export interface StoreEntry {
  type: 'challenge' | 'session';
  data: ChallengeData | SessionData;
  expiresAt: number;
}

// ===== Challenge =====

export interface ChallengeData {
  id: string;
  status: 'pending' | 'authenticated' | 'rejected' | 'expired';
  created: number;
  ican: string | null;
  coreId: string | null;
  name: string | null;
  signature: string | null;
  reason?: string;
  authenticatedAt?: number;
}

export interface ChallengeResponse {
  challengeId: string;
  loginUri: string;
  mobileUri: string;
  qrDataUrl?: string;
  expiresIn: number;
}

// ===== Session =====

export interface SessionData {
  id: string;
  ican: string;
  name: string;
  coreId: string | null;
  created: number;
}

// ===== Auth Result =====

export interface CorePassAuth {
  /** Express router — mount with app.use('/auth', auth.router) */
  router: Router;

  /** Middleware that rejects unauthenticated requests (401) */
  requireAuth: (req: Request, res: Response, next: NextFunction) => void;

  /** Get session data from request (or null) */
  getSession: (req: Request) => Promise<SessionData | null>;

  /** Stop cleanup intervals */
  destroy: () => void;
}

// ===== Internal =====

export interface ResolvedConfig {
  baseUrl: string;
  allowedIcans: string[];
  icanNames: Record<string, string>;
  sessionTtl: number;
  challengeTtl: number;
  verifySignature: boolean;
  generateQr: boolean;
  store: SessionStore;
  onAuthenticated?: (session: SessionData) => void | Promise<void>;
}
