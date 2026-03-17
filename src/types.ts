import type { Request, Response, NextFunction, Router } from 'express';

// ===== Config =====

export interface PasskeyConfig {
  /** Enable the /passkey/data endpoint */
  enabled: boolean;
  /** Endpoint path (default: '/passkey/data') */
  path?: string;
  /** Allowed timestamp drift in ms (default: 10 minutes) */
  timestampWindowMs?: number;
}

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

  /** Passkey/KYC data verification endpoint (opt-in) */
  passkey?: PasskeyConfig;

  /** Structured audit logger for login events (IP, user-agent, result) */
  auditLogger?: AuditLogger;

  /** Hook called before marking a session as authenticated — throw to reject */
  onBeforeAuthenticate?: (payload: CallbackPayload, challenge: ChallengeData) => Promise<void>;
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
  /** Deep link URI with type=app-link — CorePass redirects to conn URL with query params */
  appLinkUri: string;
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

// ===== Passkey Data =====

export interface PasskeyData {
  /** CorePass ICAN (long-form for public key extraction, or short + X-Public-Key header) */
  coreId: string;
  /** Credential identifier */
  credentialId: string;
  /** Timestamp in microseconds (Unix epoch) */
  timestamp: string;
  /** Arbitrary user data payload (KYC fields, etc.) */
  userData?: Record<string, unknown> | null;
}

export interface PasskeyResult {
  ok: true;
  coreId: string;
  credentialId: string;
  timestamp: string;
  userData: Record<string, unknown> | null;
}

// ===== Audit Logger =====

export interface AuditEvent {
  /** Event type */
  type: 'login_success' | 'login_failure' | 'login_rejected';
  /** CorePass ICAN or 'unknown' */
  userId: string;
  /** Client IP (from X-Forwarded-For or X-Real-IP) */
  ip: string;
  /** Client User-Agent */
  userAgent: string;
  /** When the event occurred */
  timestamp: Date;
  /** Reason for failure/rejection */
  reason?: string;
}

export interface AuditLogger {
  log(event: AuditEvent): Promise<void>;
}

// ===== Callback Payload =====

/** Normalized callback payload from CorePass (used by onBeforeAuthenticate hook) */
export interface CallbackPayload {
  sessionId: string;
  coreId: string;
  signature?: string;
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

export interface ResolvedPasskeyConfig {
  enabled: boolean;
  path: string;
  timestampWindowMs: number;
}

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
  passkey: ResolvedPasskeyConfig;
  auditLogger?: AuditLogger;
  onBeforeAuthenticate?: (payload: CallbackPayload, challenge: ChallengeData) => Promise<void>;
}
