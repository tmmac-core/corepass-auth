import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore } from '../src/stores/memory.js';
import { createChallenge, getChallenge, updateChallenge, deleteChallenge } from '../src/challenge.js';
import type { ResolvedConfig } from '../src/types.js';

function makeConfig(overrides?: Partial<ResolvedConfig>): ResolvedConfig {
  return {
    baseUrl: 'https://test.example.com',
    allowedIcans: [],
    icanNames: {},
    sessionTtl: 86400000,
    challengeTtl: 300000,
    verifySignature: false,
    generateQr: false,
    store: new MemoryStore(0), // No auto-cleanup in tests
    ...overrides,
  };
}

describe('Challenge', () => {
  let config: ResolvedConfig;

  beforeEach(() => {
    config = makeConfig();
  });

  it('should create a challenge with correct URIs', async () => {
    const result = await createChallenge(config);

    expect(result.challengeId).toBeDefined();
    expect(result.challengeId).toHaveLength(32); // 16 bytes hex
    expect(result.loginUri).toContain('corepass:login?sess=');
    expect(result.loginUri).toContain('type=callback');
    expect(result.mobileUri).toContain('type=app-link');
    expect(result.expiresIn).toBe(300); // 5 min
    expect(result.qrDataUrl).toBeUndefined(); // generateQr = false
  });

  it('should store challenge as pending', async () => {
    const result = await createChallenge(config);
    const challenge = await getChallenge(config, result.challengeId);

    expect(challenge).not.toBeNull();
    expect(challenge!.status).toBe('pending');
    expect(challenge!.ican).toBeNull();
    expect(challenge!.coreId).toBeNull();
  });

  it('should use correct baseUrl in URIs', async () => {
    const cfg = makeConfig({ baseUrl: 'https://my-app.com' });
    const result = await createChallenge(cfg);

    expect(result.loginUri).toContain(encodeURIComponent('https://my-app.com/auth/callback'));
    expect(result.mobileUri).toContain(encodeURIComponent('https://my-app.com/auth/app-link'));
  });

  it('should update a challenge', async () => {
    const result = await createChallenge(config);
    const challenge = await getChallenge(config, result.challengeId);

    challenge!.status = 'authenticated';
    challenge!.ican = 'CB1234567890ABCDEF1234567890ABCDEF1234567890';
    challenge!.name = 'Alice';
    await updateChallenge(config, result.challengeId, challenge!);

    const updated = await getChallenge(config, result.challengeId);
    expect(updated!.status).toBe('authenticated');
    expect(updated!.ican).toBe('CB1234567890ABCDEF1234567890ABCDEF1234567890');
  });

  it('should delete a challenge', async () => {
    const result = await createChallenge(config);
    await deleteChallenge(config, result.challengeId);

    const challenge = await getChallenge(config, result.challengeId);
    expect(challenge).toBeNull();
  });

  it('should return null for non-existent challenge', async () => {
    const challenge = await getChallenge(config, 'nonexistent');
    expect(challenge).toBeNull();
  });
});
