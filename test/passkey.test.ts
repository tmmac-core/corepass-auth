import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import { corepassAuth } from '../src/index.js';
import { canonicalJson, extractPublicKey, extractPublicKeyFromHeader, hexToBytes } from '../src/crypto/ed448.js';
import type { CorePassAuth } from '../src/types.js';

// ===== Test fixtures =====

// A fake 118-char long-form ICAN: CB + 2 check digits + 114 hex (57 bytes BBAN)
const LONG_ICAN = 'CB00' + 'AA'.repeat(57);
const SHORT_ICAN = 'CB1234567890ABCDEF1234567890ABCDEF1234567890';

function createTestApp(config?: Record<string, unknown>) {
  const app = express();
  app.use(express.json());

  const auth = corepassAuth({
    baseUrl: 'http://localhost:9999',
    passkey: { enabled: true },
    ...config,
  });

  app.use('/auth', auth.router);
  return { app, auth };
}

function createTestAppWithoutPasskey() {
  const app = express();
  app.use(express.json());

  const auth = corepassAuth({
    baseUrl: 'http://localhost:9999',
    // passkey not configured → endpoint should not exist
  });

  app.use('/auth', auth.router);
  return { app, auth };
}

async function request(
  app: express.Application,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
) {
  return new Promise<{ status: number; body: any }>((resolve) => {
    const server = app.listen(0, () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const opts: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        body: body ? JSON.stringify(body) : undefined,
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
        resolve({ status: res.status, body: responseBody });
      });
    });
  });
}

// ===== Unit Tests: canonicalJson (extended) =====

describe('canonicalJson (extended)', () => {
  it('should handle arrays', () => {
    expect(canonicalJson([1, 2, 3])).toBe('[1,2,3]');
  });

  it('should handle nested arrays in objects', () => {
    expect(canonicalJson({ b: [3, 1], a: 'x' })).toBe('{"a":"x","b":[3,1]}');
  });

  it('should handle deeply nested structures', () => {
    const input = { z: { y: [{ b: 2, a: 1 }] }, a: null };
    expect(canonicalJson(input)).toBe('{"a":null,"z":{"y":[{"a":1,"b":2}]}}');
  });

  it('should handle primitive values directly', () => {
    expect(canonicalJson('hello')).toBe('"hello"');
    expect(canonicalJson(42)).toBe('42');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(null)).toBe('null');
  });
});

// ===== Unit Tests: extractPublicKeyFromHeader =====

describe('extractPublicKeyFromHeader', () => {
  it('should extract from X-Public-Key header (hex)', () => {
    const hexKey = 'aa'.repeat(57); // 114 hex chars = 57 bytes
    const result = extractPublicKeyFromHeader({ 'x-public-key': hexKey }, SHORT_ICAN);
    expect(result.length).toBe(57);
    expect(result[0]).toBe(0xAA);
  });

  it('should extract from X-Public-Key header (base64)', () => {
    const bytes = new Uint8Array(57).fill(0xBB);
    const b64 = Buffer.from(bytes).toString('base64');
    const result = extractPublicKeyFromHeader({ 'x-public-key': b64 }, SHORT_ICAN);
    expect(result.length).toBe(57);
    expect(result[0]).toBe(0xBB);
  });

  it('should fall back to long-form ICAN when no header', () => {
    const result = extractPublicKeyFromHeader({}, LONG_ICAN);
    expect(result.length).toBe(57);
    expect(result[0]).toBe(0xAA);
  });

  it('should throw for short-form ICAN without X-Public-Key', () => {
    expect(() => extractPublicKeyFromHeader({}, SHORT_ICAN))
      .toThrow('Short-form ICAN cannot be used');
  });

  it('should throw for invalid X-Public-Key length', () => {
    expect(() => extractPublicKeyFromHeader({ 'x-public-key': 'aabb' }, SHORT_ICAN))
      .toThrow('X-Public-Key must be 57 bytes');
  });
});

// ===== Unit Tests: hexToBytes =====

describe('hexToBytes', () => {
  it('should convert valid hex', () => {
    const result = hexToBytes('aabbcc');
    expect(result).toEqual(new Uint8Array([0xAA, 0xBB, 0xCC]));
  });

  it('should handle 0x prefix', () => {
    const result = hexToBytes('0xaabb');
    expect(result).toEqual(new Uint8Array([0xAA, 0xBB]));
  });

  it('should throw on invalid hex', () => {
    expect(() => hexToBytes('xyz')).toThrow('Invalid hex string');
  });

  it('should throw on odd-length hex', () => {
    expect(() => hexToBytes('aab')).toThrow('Invalid hex string');
  });
});

// ===== Integration Tests: POST /auth/passkey/data =====

describe('POST /auth/passkey/data', () => {
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

  it('should reject missing required fields', async () => {
    const res = await request(app, 'POST', '/auth/passkey/data', {});
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBe('missing_fields');
  });

  it('should reject missing coreId', async () => {
    const res = await request(app, 'POST', '/auth/passkey/data', {
      credentialId: 'cred-1',
      timestamp: String(BigInt(Date.now()) * 1000n),
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_fields');
  });

  it('should reject missing X-Signature header', async () => {
    const res = await request(app, 'POST', '/auth/passkey/data', {
      coreId: LONG_ICAN,
      credentialId: 'cred-1',
      timestamp: String(BigInt(Date.now()) * 1000n),
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_signature');
  });

  it('should reject expired timestamp', async () => {
    // Timestamp 20 minutes in the past (beyond 10min window)
    const oldTimestamp = String((BigInt(Date.now()) - 20n * 60n * 1000n) * 1000n);
    const res = await request(
      app,
      'POST',
      '/auth/passkey/data',
      {
        coreId: LONG_ICAN,
        credentialId: 'cred-1',
        timestamp: oldTimestamp,
      },
      { 'x-signature': 'aa'.repeat(57) },
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('verification_failed');
    expect(res.body.details).toContain('Timestamp out of range');
  });

  it('should reject invalid signature (valid timestamp, bad sig)', async () => {
    const nowMicros = String(BigInt(Date.now()) * 1000n);
    const res = await request(
      app,
      'POST',
      '/auth/passkey/data',
      {
        coreId: LONG_ICAN,
        credentialId: 'cred-1',
        timestamp: nowMicros,
        userData: { name: 'Test' },
      },
      { 'x-signature': 'bb'.repeat(57) },
    );
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBe('verification_failed');
  });

  it('should reject short-form ICAN without X-Public-Key', async () => {
    const nowMicros = String(BigInt(Date.now()) * 1000n);
    const res = await request(
      app,
      'POST',
      '/auth/passkey/data',
      {
        coreId: SHORT_ICAN,
        credentialId: 'cred-1',
        timestamp: nowMicros,
      },
      { 'x-signature': 'cc'.repeat(57) },
    );
    expect(res.status).toBe(400);
    expect(res.body.details).toContain('Short-form ICAN');
  });
});

// ===== Endpoint disabled when passkey not configured =====

describe('Passkey endpoint disabled', () => {
  let auth: CorePassAuth;
  let app: express.Application;

  beforeEach(() => {
    const result = createTestAppWithoutPasskey();
    app = result.app;
    auth = result.auth;
  });

  afterEach(() => {
    auth.destroy();
  });

  it('should return 404 when passkey is not enabled', async () => {
    const res = await request(app, 'POST', '/auth/passkey/data', {
      coreId: LONG_ICAN,
      credentialId: 'cred-1',
      timestamp: String(BigInt(Date.now()) * 1000n),
    });
    // Express returns 404 for unmatched routes
    expect(res.status).toBe(404);
  });
});
