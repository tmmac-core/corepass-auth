import type { SessionStore, StoreEntry } from '../types.js';

/**
 * In-memory store with automatic TTL expiration.
 * Default store — suitable for single-process deployments.
 * For multi-process/cluster setups, use a Redis-based store.
 */
export class MemoryStore implements SessionStore {
  private store = new Map<string, StoreEntry>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs = 60_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    // Don't keep the process alive just for cleanup
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  async set(key: string, value: StoreEntry, ttlMs: number): Promise<void> {
    this.store.set(key, {
      ...value,
      expiresAt: Date.now() + ttlMs,
    });
  }

  async get(key: string): Promise<StoreEntry | null> {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry;
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
      }
    }
  }

  /** Stop the cleanup timer (call on shutdown) */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /** Current number of entries (for health checks) */
  get size(): number {
    return this.store.size;
  }
}
