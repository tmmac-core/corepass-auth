import { describe, it, expect } from 'vitest';
import { normalizeIcan, isValidIcanFormat, isIcanAllowed, getIcanName } from '../src/crypto/ican.js';
import { extractPublicKey, canonicalJson } from '../src/crypto/ed448.js';

describe('ICAN Utilities', () => {
  const VALID_ICAN = 'CB1234567890ABCDEF1234567890ABCDEF1234567890';

  describe('normalizeIcan', () => {
    it('should uppercase and trim', () => {
      expect(normalizeIcan(' cb1234567890abcdef1234567890abcdef1234567890 '))
        .toBe('CB1234567890ABCDEF1234567890ABCDEF1234567890');
    });
  });

  describe('isValidIcanFormat', () => {
    it('should accept valid ICAN', () => {
      expect(isValidIcanFormat(VALID_ICAN)).toBe(true);
    });

    it('should reject too short', () => {
      expect(isValidIcanFormat('CB1234')).toBe(false);
    });

    it('should reject without CB prefix', () => {
      expect(isValidIcanFormat('XX1234567890ABCDEF1234567890ABCDEF1234567890')).toBe(false);
    });

    it('should reject non-hex characters', () => {
      expect(isValidIcanFormat('CB1234567890ABCDEF1234567890ABCDEF12345XYZ90')).toBe(false);
    });
  });

  describe('isIcanAllowed', () => {
    it('should allow all when whitelist is empty', () => {
      expect(isIcanAllowed(VALID_ICAN, [])).toBe(true);
    });

    it('should allow whitelisted ICAN', () => {
      expect(isIcanAllowed(VALID_ICAN, [VALID_ICAN])).toBe(true);
    });

    it('should allow case-insensitive match', () => {
      expect(isIcanAllowed(VALID_ICAN.toLowerCase(), [VALID_ICAN])).toBe(true);
    });

    it('should reject non-whitelisted ICAN', () => {
      expect(isIcanAllowed(VALID_ICAN, ['CB0000000000000000000000000000000000000000FF'])).toBe(false);
    });
  });

  describe('getIcanName', () => {
    it('should return mapped name', () => {
      expect(getIcanName(VALID_ICAN, { [VALID_ICAN]: 'Alice' })).toBe('Alice');
    });

    it('should return truncated ICAN when no name mapped', () => {
      expect(getIcanName(VALID_ICAN, {})).toBe('CB12345678...');
    });
  });
});

describe('Ed448 Utilities', () => {
  describe('extractPublicKey', () => {
    it('should return null for short-form ICAN (44 chars)', () => {
      const shortIcan = 'CB1234567890ABCDEF1234567890ABCDEF1234567890';
      expect(extractPublicKey(shortIcan)).toBeNull();
    });

    it('should extract 57 bytes from long-form ICAN (118 chars)', () => {
      // Construct a fake 118-char long-form ICAN
      const longIcan = 'CB00' + 'AA'.repeat(57); // CB + 2 check + 114 hex
      const pubKey = extractPublicKey(longIcan);
      expect(pubKey).not.toBeNull();
      expect(pubKey!.length).toBe(57);
      expect(pubKey![0]).toBe(0xAA);
    });

    it('should return null for non-CB prefix', () => {
      const bad = 'XX00' + 'AA'.repeat(57);
      expect(extractPublicKey(bad)).toBeNull();
    });
  });

  describe('canonicalJson', () => {
    it('should sort keys alphabetically', () => {
      expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    });

    it('should handle nested objects', () => {
      expect(canonicalJson({ z: { b: 2, a: 1 }, a: 'x' })).toBe('{"a":"x","z":{"a":1,"b":2}}');
    });

    it('should skip undefined values', () => {
      expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    });

    it('should handle strings', () => {
      expect(canonicalJson({ session: 'abc', coreID: 'def' }))
        .toBe('{"coreID":"def","session":"abc"}');
    });
  });
});
