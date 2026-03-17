import { Router } from 'express';
import type { Request, Response } from 'express';
import type { ResolvedConfig, ChallengeData, PasskeyData, CallbackPayload } from './types.js';
import type { AuditEvent } from './types.js';
import { createChallenge, getChallenge, updateChallenge, deleteChallenge } from './challenge.js';
import { createSession, getSession, extractToken, destroySession } from './session.js';
import { normalizeIcan, isIcanAllowed, getIcanName } from './crypto/ican.js';
import { verifyEd448Signature } from './crypto/ed448.js';
import { verifyPasskeyData } from './crypto/passkey.js';
import { getMobileRedirectHtml } from './widget/mobile.js';

/**
 * Normalize CorePass callback field names.
 * Why: CorePass sends coreID (capital D), but integrators might send coreId.
 * Same for session vs sessionId. This prevents support issues from field name mismatches.
 */
function normalizePayload(body: Record<string, unknown>): CallbackPayload {
  return {
    sessionId: String(body?.session || body?.sessionId || ''),
    coreId: String(body?.coreID || body?.coreId || ''),
    signature: body?.signature ? String(body.signature) : undefined,
  };
}

/** Extract client IP from request headers (for audit logging) */
function getClientIp(headers: Record<string, string | string[] | undefined>): string {
  const forwarded = headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  const realIp = headers['x-real-ip'];
  if (typeof realIp === 'string') return realIp;
  return '';
}

/** Build audit base fields from a request */
function buildAuditBase(req: Request): Omit<AuditEvent, 'type' | 'userId'> {
  return {
    ip: getClientIp(req.headers),
    userAgent: String(req.headers['user-agent'] || ''),
    timestamp: new Date(),
  };
}

/** Log an audit event if a logger is configured */
async function auditLog(
  config: ResolvedConfig,
  base: Omit<AuditEvent, 'type' | 'userId'>,
  type: AuditEvent['type'],
  userId: string,
  reason?: string,
): Promise<void> {
  if (config.auditLogger) {
    await config.auditLogger.log({ ...base, type, userId, reason });
  }
}

/** Build the widget JS bundle (loaded lazily) */
let widgetBundle: string | null = null;

async function getWidgetBundle(): Promise<string> {
  if (widgetBundle) return widgetBundle;
  try {
    // In production, the widget is pre-built into dist/widget.js
    const fs = await import('fs');
    const path = await import('path');
    const widgetPath = path.default.join(__dirname, 'widget.js');
    widgetBundle = fs.default.readFileSync(widgetPath, 'utf-8');
  } catch {
    widgetBundle = '// Widget bundle not found. Run: npm run build:widget';
  }
  return widgetBundle;
}

export function createRouter(config: ResolvedConfig): Router {
  const router = Router();

  // ===== POST /challenge — Create new login challenge =====
  router.post('/challenge', async (_req: Request, res: Response) => {
    try {
      const challenge = await createChallenge(config);
      res.json(challenge);
    } catch (err) {
      console.error('[CorePassAuth] Challenge creation failed:', err);
      res.status(500).json({ error: 'Challenge creation failed' });
    }
  });

  // ===== POST /callback — CorePass app callback after QR scan =====
  router.post('/callback', async (req: Request, res: Response) => {
    const { sessionId, coreId: coreID, signature } = normalizePayload(req.body || {});

    if (!sessionId || !coreID) {
      return res.status(400).json({ error: 'Missing session or coreID' });
    }

    const challenge = await getChallenge(config, sessionId);
    if (!challenge) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (challenge.status !== 'pending') {
      return res.status(409).json({ error: 'Session already processed' });
    }

    const ican = normalizeIcan(coreID);
    const audit = buildAuditBase(req);

    // Whitelist check
    if (!isIcanAllowed(ican, config.allowedIcans)) {
      console.log(`[CorePassAuth] ICAN not whitelisted: ${ican}`);
      challenge.status = 'rejected';
      challenge.reason = 'ICAN not whitelisted';
      await updateChallenge(config, sessionId, challenge);
      await auditLog(config, audit, 'login_rejected', ican, 'ICAN not whitelisted');
      return res.status(403).json({ error: 'ICAN nicht autorisiert' });
    }

    // Optional Ed448 signature verification
    if (config.verifySignature && signature) {
      const valid = await verifyEd448Signature(coreID, signature, {
        session: sessionId,
        coreID,
      });
      if (!valid) {
        console.log(`[CorePassAuth] Invalid signature for: ${ican}`);
        challenge.status = 'rejected';
        challenge.reason = 'Invalid signature';
        await updateChallenge(config, sessionId, challenge);
        await auditLog(config, audit, 'login_failure', ican, 'Invalid signature');
        return res.status(403).json({ error: 'Signatur ungueltig' });
      }
    }

    // Optional pre-authentication hook — allows custom validation before accepting
    if (config.onBeforeAuthenticate) {
      try {
        await config.onBeforeAuthenticate({ sessionId, coreId: coreID, signature }, { ...challenge });
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'Pre-auth hook rejected';
        console.log(`[CorePassAuth] Pre-auth hook rejected: ${reason}`);
        challenge.status = 'rejected';
        challenge.reason = reason;
        await updateChallenge(config, sessionId, challenge);
        await auditLog(config, audit, 'login_rejected', ican, reason);
        // Don't leak internal hook error details to the client
        return res.status(403).json({ error: 'Authentication rejected' });
      }
    }

    // Mark as authenticated
    const name = getIcanName(ican, config.icanNames);
    challenge.status = 'authenticated';
    challenge.ican = ican;
    challenge.name = name;
    challenge.coreId = coreID;
    challenge.signature = signature || null;
    challenge.authenticatedAt = Date.now();
    await updateChallenge(config, sessionId, challenge);

    console.log(`[CorePassAuth] Authenticated: ${name} (${ican})`);
    await auditLog(config, audit, 'login_success', ican);
    res.json({ status: 'ok', ican, name });
  });

  // ===== GET /app-link — CorePass mobile redirect callback =====
  router.get('/app-link', async (req: Request, res: Response) => {
    const { sessionId, coreId: coreID, signature } = normalizePayload(req.query as Record<string, unknown>);

    if (!sessionId || !coreID) {
      return res.redirect('/?error=missing_params');
    }

    const challenge = await getChallenge(config, sessionId);
    if (!challenge) {
      return res.redirect('/?error=session_not_found');
    }

    if (challenge.status !== 'pending') {
      return res.redirect('/?error=session_already_processed');
    }

    const ican = normalizeIcan(coreID);
    const audit = buildAuditBase(req);

    if (!isIcanAllowed(ican, config.allowedIcans)) {
      console.log(`[CorePassAuth] app-link: ICAN not whitelisted: ${ican}`);
      await deleteChallenge(config, sessionId);
      await auditLog(config, audit, 'login_rejected', ican, 'ICAN not whitelisted (app-link)');
      return res.redirect('/?error=not_whitelisted');
    }

    // Optional signature verification
    if (config.verifySignature && signature) {
      const valid = await verifyEd448Signature(coreID, signature, {
        session: sessionId,
        coreID,
      });
      if (!valid) {
        await deleteChallenge(config, sessionId);
        await auditLog(config, audit, 'login_failure', ican, 'Invalid signature (app-link)');
        return res.redirect('/?error=invalid_signature');
      }
    }

    // Optional pre-authentication hook
    if (config.onBeforeAuthenticate) {
      try {
        await config.onBeforeAuthenticate({ sessionId, coreId: coreID, signature }, { ...challenge });
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'Pre-auth hook rejected';
        console.log(`[CorePassAuth] app-link: Pre-auth hook rejected: ${reason}`);
        await deleteChallenge(config, sessionId);
        await auditLog(config, audit, 'login_rejected', ican, reason);
        return res.redirect(`/?error=rejected`);
      }
    }

    // Create app session + redirect with token
    const appSession = await createSession(config, ican, coreID);
    await deleteChallenge(config, sessionId);

    const name = encodeURIComponent(appSession.name);
    console.log(`[CorePassAuth] app-link: Authenticated: ${appSession.name} (${ican})`);
    await auditLog(config, audit, 'login_success', ican);
    res.redirect(`/?token=${appSession.id}&name=${name}`);
  });

  // ===== GET /challenge/:id — Poll challenge status =====
  router.get('/challenge/:id', async (req: Request, res: Response) => {
    const id = String(req.params.id);
    const challenge = await getChallenge(config, id);

    if (!challenge) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (challenge.status === 'authenticated') {
      // Create app session and return token
      const appSession = await createSession(config, challenge.ican!, challenge.coreId);
      await deleteChallenge(config, id);
      return res.json({
        status: 'authenticated',
        token: appSession.id,
        ican: challenge.ican,
        name: challenge.name,
      });
    }

    if (challenge.status === 'rejected') {
      await deleteChallenge(config, id);
      return res.json({ status: 'rejected', reason: challenge.reason });
    }

    res.json({ status: 'pending' });
  });

  // ===== GET /session — Check current session =====
  router.get('/session', async (req: Request, res: Response) => {
    const token = extractToken(req);

    if (!token) {
      return res.json({ authenticated: false });
    }

    const session = await getSession(config, token);
    if (!session) {
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      ican: session.ican,
      name: session.name,
    });
  });

  // ===== POST /logout — Destroy session =====
  router.post('/logout', async (req: Request, res: Response) => {
    const token = extractToken(req);

    if (token) {
      await destroySession(config, token);
    }

    res.json({ ok: true });
  });

  // ===== GET /widget.js — Serve the frontend widget =====
  router.get('/widget.js', async (_req: Request, res: Response) => {
    const bundle = await getWidgetBundle();
    res.set('Content-Type', 'application/javascript; charset=utf-8');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(bundle);
  });

  // ===== POST /passkey/data — Verify signed CorePass data (opt-in) =====
  if (config.passkey.enabled) {
    const passkeyPath = config.passkey.path;
    router.post(passkeyPath, async (req: Request, res: Response) => {
      try {
        const body = req.body as PasskeyData;

        if (!body.coreId || !body.credentialId || !body.timestamp) {
          return res.status(400).json({
            ok: false,
            error: 'missing_fields',
            details: 'coreId, credentialId and timestamp are required',
          });
        }

        const signatureHeader = req.headers['x-signature'];
        const signature = typeof signatureHeader === 'string' ? signatureHeader : undefined;
        if (!signature) {
          return res.status(400).json({
            ok: false,
            error: 'missing_signature',
            details: 'X-Signature header is required',
          });
        }

        await verifyPasskeyData(body, signature, req.headers, config.passkey);

        console.log(`[CorePassAuth] Passkey verified: ${body.coreId}`);
        return res.json({
          ok: true,
          coreId: body.coreId,
          credentialId: body.credentialId,
          timestamp: body.timestamp,
          userData: body.userData || null,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.log(`[CorePassAuth] Passkey verification failed: ${message}`);
        return res.status(400).json({
          ok: false,
          error: 'verification_failed',
          details: message,
        });
      }
    });
  }

  // ===== GET /mobile-redirect — Intermediate page for mobile deep link =====
  router.get('/mobile-redirect', async (req: Request, res: Response) => {
    const challengeId = req.query.challengeId ? String(req.query.challengeId) : '';

    if (!challengeId) {
      return res.status(400).send('Missing challengeId');
    }

    const challenge = await getChallenge(config, challengeId);
    if (!challenge) {
      return res.status(404).send('Challenge not found or expired');
    }

    const callbackUrl = `${config.baseUrl}/auth/callback`;
    const corepassUri = `corepass:login/?sess=${encodeURIComponent(challengeId)}&conn=${encodeURIComponent(callbackUrl)}&type=callback`;

    const html = getMobileRedirectHtml(corepassUri);
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });

  return router;
}
