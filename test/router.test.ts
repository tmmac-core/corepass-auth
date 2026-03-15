import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import { corepassAuth } from '../src/index.js';
import type { CorePassAuth } from '../src/types.js';

const TEST_ICAN = 'CB1234567890ABCDEF1234567890ABCDEF1234567890';

function createTestApp(config?: Record<string, unknown>) {
  const app = express();
  app.use(express.json());

  const auth = corepassAuth({
    baseUrl: 'http://localhost:9999',
    allowedIcans: [TEST_ICAN],
    icanNames: { [TEST_ICAN]: 'TestUser' },
    ...config,
  });

  app.use('/auth', auth.router);
  app.get('/protected', auth.requireAuth, (_req, res) => {
    res.json({ ok: true, session: (_req as any).corepassSession });
  });

  return { app, auth };
}

/** Simple fetch-like helper using the express app directly */
async function request(app: express.Application, method: string, path: string, body?: unknown, headers?: Record<string, string>) {
  return new Promise<{ status: number; body: any; headers: Record<string, string> }>((resolve) => {
    const server = app.listen(0, () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const opts: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        body: body ? JSON.stringify(body) : undefined,
        redirect: 'manual',
      };
      fetch(url, opts).then(async (res) => {
        let responseBody: any;
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('json')) {
          responseBody = await res.json();
        } else {
          responseBody = await res.text();
        }
        server.close();
        resolve({
          status: res.status,
          body: responseBody,
          headers: Object.fromEntries(res.headers.entries()),
        });
      });
    });
  });
}

describe('Router Endpoints', () => {
  let auth: CorePassAuth;
  let app: express.Application;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    auth = result.auth;
  });

  afterEach(() => {
    auth.destroy();
  });

  describe('POST /auth/challenge', () => {
    it('should create a challenge', async () => {
      const res = await request(app, 'POST', '/auth/challenge');
      expect(res.status).toBe(200);
      expect(res.body.challengeId).toBeDefined();
      expect(res.body.loginUri).toContain('corepass:login');
      expect(res.body.mobileUri).toContain('type=app-link');
      expect(res.body.expiresIn).toBe(300);
    });
  });

  describe('POST /auth/callback', () => {
    it('should authenticate with valid ICAN', async () => {
      // Create challenge first
      const challenge = await request(app, 'POST', '/auth/challenge');
      const challengeId = challenge.body.challengeId;

      // Simulate CorePass callback
      const res = await request(app, 'POST', '/auth/callback', {
        session: challengeId,
        coreID: TEST_ICAN,
      });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.ican).toBe(TEST_ICAN);
      expect(res.body.name).toBe('TestUser');
    });

    it('should reject non-whitelisted ICAN', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      const res = await request(app, 'POST', '/auth/callback', {
        session: challenge.body.challengeId,
        coreID: 'CB0000000000000000000000000000000000000000FF',
      });
      expect(res.status).toBe(403);
    });

    it('should reject missing params', async () => {
      const res = await request(app, 'POST', '/auth/callback', {});
      expect(res.status).toBe(400);
    });

    it('should reject unknown session', async () => {
      const res = await request(app, 'POST', '/auth/callback', {
        session: 'nonexistent',
        coreID: TEST_ICAN,
      });
      expect(res.status).toBe(404);
    });
  });

  describe('GET /auth/challenge/:id (polling)', () => {
    it('should return pending for new challenge', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      const res = await request(app, 'GET', `/auth/challenge/${challenge.body.challengeId}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('pending');
    });

    it('should return authenticated with token after callback', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      const challengeId = challenge.body.challengeId;

      // Simulate callback
      await request(app, 'POST', '/auth/callback', {
        session: challengeId,
        coreID: TEST_ICAN,
      });

      // Poll
      const res = await request(app, 'GET', `/auth/challenge/${challengeId}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('authenticated');
      expect(res.body.token).toBeDefined();
      expect(res.body.ican).toBe(TEST_ICAN);
      expect(res.body.name).toBe('TestUser');
    });

    it('should return 404 for unknown challenge', async () => {
      const res = await request(app, 'GET', '/auth/challenge/nonexistent');
      expect(res.status).toBe(404);
    });
  });

  describe('Protected routes', () => {
    it('should reject without token', async () => {
      const res = await request(app, 'GET', '/protected');
      expect(res.status).toBe(401);
    });

    it('should accept with valid session token', async () => {
      // Full flow: challenge → callback → poll → get token
      const challenge = await request(app, 'POST', '/auth/challenge');
      await request(app, 'POST', '/auth/callback', {
        session: challenge.body.challengeId,
        coreID: TEST_ICAN,
      });
      const poll = await request(app, 'GET', `/auth/challenge/${challenge.body.challengeId}`);
      const token = poll.body.token;

      const res = await request(app, 'GET', '/protected', undefined, {
        'x-session-token': token,
      });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.session.ican).toBe(TEST_ICAN);
    });

    it('should accept Bearer token', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      await request(app, 'POST', '/auth/callback', {
        session: challenge.body.challengeId,
        coreID: TEST_ICAN,
      });
      const poll = await request(app, 'GET', `/auth/challenge/${challenge.body.challengeId}`);

      const res = await request(app, 'GET', '/protected', undefined, {
        Authorization: `Bearer ${poll.body.token}`,
      });
      expect(res.status).toBe(200);
    });
  });

  describe('POST /auth/logout', () => {
    it('should destroy session', async () => {
      // Create session
      const challenge = await request(app, 'POST', '/auth/challenge');
      await request(app, 'POST', '/auth/callback', {
        session: challenge.body.challengeId,
        coreID: TEST_ICAN,
      });
      const poll = await request(app, 'GET', `/auth/challenge/${challenge.body.challengeId}`);
      const token = poll.body.token;

      // Logout
      const logout = await request(app, 'POST', '/auth/logout', undefined, {
        'x-session-token': token,
      });
      expect(logout.body.ok).toBe(true);

      // Token should be invalid now
      const res = await request(app, 'GET', '/protected', undefined, {
        'x-session-token': token,
      });
      expect(res.status).toBe(401);
    });
  });

  describe('GET /auth/session', () => {
    it('should return authenticated:false without token', async () => {
      const res = await request(app, 'GET', '/auth/session');
      expect(res.body.authenticated).toBe(false);
    });

    it('should return session data with valid token', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      await request(app, 'POST', '/auth/callback', {
        session: challenge.body.challengeId,
        coreID: TEST_ICAN,
      });
      const poll = await request(app, 'GET', `/auth/challenge/${challenge.body.challengeId}`);

      const res = await request(app, 'GET', '/auth/session', undefined, {
        'x-session-token': poll.body.token,
      });
      expect(res.body.authenticated).toBe(true);
      expect(res.body.ican).toBe(TEST_ICAN);
      expect(res.body.name).toBe('TestUser');
    });
  });

  describe('GET /auth/mobile-redirect', () => {
    it('should return HTML page with corepass: URI', async () => {
      const challenge = await request(app, 'POST', '/auth/challenge');
      const res = await request(app, 'GET', `/auth/mobile-redirect?challengeId=${challenge.body.challengeId}`);
      expect(res.status).toBe(200);
      expect(res.body).toContain('corepass:login');
      expect(res.body).toContain('cplink');
    });

    it('should return 400 without challengeId', async () => {
      const res = await request(app, 'GET', '/auth/mobile-redirect');
      expect(res.status).toBe(400);
    });

    it('should return 404 for expired challenge', async () => {
      const res = await request(app, 'GET', '/auth/mobile-redirect?challengeId=nonexistent');
      expect(res.status).toBe(404);
    });
  });
});
