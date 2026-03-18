# @tmmac/corepass-auth

Drop-in [CorePass](https://corepass.net) authentication for Express.js.
QR-code login on desktop. Deep-link login on mobile. One line to integrate.

```js
app.use('/auth', corepassAuth({ baseUrl: 'https://your-app.com' }).router);
// That's it. Your app now has CorePass authentication.
```

## Why CorePass Auth?

CorePass is the identity layer of [Core Blockchain](https://corecoin.cc) — a self-sovereign wallet that lets users prove who they are without passwords, emails, or third-party OAuth. This middleware handles the full login flow so you don't have to.

- **Zero passwords** — users authenticate by scanning a QR code or tapping a deep link
- **One dependency** — no passport.js, no session libraries, no cookie parsers
- **Works everywhere** — desktop browsers get a QR code, mobile browsers get a native deep link
- **Production-ready** — audit logging, replay protection, ICAN whitelisting, pluggable session stores

## Features

- **Desktop:** QR code scanning with real-time polling
- **Mobile:** Deep link to CorePass app with automatic device detection + QR fallback
- **Frontend widget:** Self-contained `<script>` tag — no framework needed
- **Ed448 signature verification** (optional, via `@noble/curves`)
- **Passkey/KYC data verification** — verify signed CorePass data payloads
- **Pre-auth hook** — run custom checks before accepting a login (blocklists, rate limits, etc.)
- **Audit logging** — structured login events with IP, user-agent, and result
- **Pluggable session store** — built-in MemoryStore, or bring your own (Redis, DB, etc.)
- **ICAN whitelist** — restrict login to specific Core Blockchain addresses
- **Dual build:** ESM + CommonJS + IIFE widget bundle

## Installation

```bash
npm install @tmmac/corepass-auth
```

Express is a peer dependency:

```bash
npm install express
```

Optional dependencies for extended features:

```bash
npm install @noble/curves  # Ed448 signature verification
npm install qrcode         # Server-side QR code generation
```

## Quick Start

```js
import express from 'express';
import { corepassAuth } from '@tmmac/corepass-auth';

const app = express();
app.use(express.json());

const auth = corepassAuth({
  baseUrl: 'https://your-app.com',
  allowedIcans: ['CB1234567890ABCDEF1234567890ABCDEF1234567890'],
  icanNames: {
    'CB1234567890ABCDEF1234567890ABCDEF1234567890': 'Alice',
  },
});

// Mount auth routes
app.use('/auth', auth.router);

// Protect your routes
app.get('/api/data', auth.requireAuth, (req, res) => {
  const session = req.corepassSession;
  res.json({ user: session.name, ican: session.ican });
});

app.listen(3000);
```

## Frontend Widget

The middleware serves a ready-to-use login widget. No React, no build step — just a script tag:

```html
<div id="corepass-login"></div>
<script src="/auth/widget.js"></script>
<script>
  CorePassWidget.init({
    container: '#corepass-login',
    authPath: '/auth',
    onSuccess: ({ token, ican, name }) => {
      localStorage.setItem('token', token);
      window.location.href = '/dashboard';
    },
    theme: 'dark', // 'dark' | 'light'
    locale: 'en',  // 'en' | 'de'
  });
</script>
```

The widget automatically detects the device — shows a QR code on desktop and a deep-link button on mobile.

## Auth Flow

```
Desktop:                              Mobile:
┌──────────┐                          ┌──────────┐
│  Browser  │                          │  Browser  │
│  shows QR │                          │  opens    │
│           │                          │ deep link │
└─────┬─────┘                          └─────┬─────┘
      │ scan                                 │
┌─────▼─────┐                          ┌─────▼─────┐
│  CorePass  │                          │  CorePass  │
│    App     │                          │    App     │
└─────┬─────┘                          └─────┬─────┘
      │ POST /callback                       │ GET /app-link
┌─────▼─────┐                          ┌─────▼─────┐
│   Server   │                          │   Server   │
│  verifies  │                          │  verifies  │
│ + session  │                          │ + redirect │
└─────┬─────┘                          └─────┬─────┘
      │ Poll: GET /challenge/:id             │ ?token=...
┌─────▼─────┐                          ┌─────▼─────┐
│  Browser   │                          │  Browser   │
│ logged in  │                          │ logged in  │
└────────────┘                          └────────────┘
```

## Configuration

```ts
const auth = corepassAuth({
  // Required: your app's public URL
  baseUrl: 'https://your-app.com',

  // Optional: restrict login to specific ICANs (empty = allow all)
  allowedIcans: ['CB1234...ABCD', 'CB5678...EF12'],

  // Optional: map ICANs to display names
  icanNames: {
    'CB1234...ABCD': 'Alice',
    'CB5678...EF12': 'Bob',
  },

  // Optional: session settings
  session: {
    ttl: 24 * 60 * 60 * 1000,      // App session lifetime (default: 24h)
    challengeTtl: 5 * 60 * 1000,    // Login challenge lifetime (default: 5min)
  },

  // Optional: verify Ed448 signatures from CorePass (requires @noble/curves)
  verifySignature: false,

  // Optional: generate QR codes server-side (requires qrcode package)
  generateQr: false,

  // Optional: custom session store (default: MemoryStore)
  store: new RedisStore(),

  // Optional: hook after successful login
  onAuthenticated: (session) => {
    console.log(`${session.name} logged in`);
  },

  // Optional: hook before accepting a login — throw to reject
  onBeforeAuthenticate: async (payload, challenge) => {
    if (await isBlocked(payload.coreId)) {
      throw new Error('Account suspended');
    }
  },

  // Optional: structured audit logging
  auditLogger: {
    log: async (event) => {
      // event: { type, userId, ip, userAgent, timestamp, reason? }
      await db.auditLogs.insert(event);
    },
  },

  // Optional: passkey/KYC data verification endpoint
  passkey: {
    enabled: true,
    path: '/passkey/data',            // default
    timestampWindowMs: 10 * 60 * 1000, // default: 10 minutes
  },
});
```

## API

### Returned Object

`corepassAuth(config)` returns:

| Property | Type | Description |
|---|---|---|
| `router` | `Router` | Express router — mount with `app.use('/auth', auth.router)` |
| `requireAuth` | `Middleware` | Rejects unauthenticated requests with 401 |
| `getSession` | `(req) => Promise<SessionData \| null>` | Get the current session from a request |
| `destroy` | `() => void` | Stop cleanup intervals (call on shutdown) |

### Endpoints

All endpoints are relative to your mount path (e.g., `/auth`):

| Method | Path | Description |
|---|---|---|
| `POST` | `/challenge` | Create a new login challenge |
| `POST` | `/callback` | CorePass callback after QR scan (desktop) |
| `GET` | `/app-link` | CorePass redirect callback (mobile) |
| `GET` | `/challenge/:id` | Poll challenge status |
| `GET` | `/session` | Check current session |
| `POST` | `/logout` | Destroy session |
| `GET` | `/widget.js` | Serve the frontend widget bundle |
| `GET` | `/mobile-redirect` | Intermediate page for mobile deep link |
| `POST` | `/passkey/data` | Verify signed CorePass data (opt-in) |

### Session Data

When `requireAuth` succeeds, the session is attached to the request:

```ts
app.get('/profile', auth.requireAuth, (req, res) => {
  const session = req.corepassSession;
  // session.id     — session token
  // session.ican   — Core Blockchain ICAN address
  // session.name   — display name (from icanNames, or shortened ICAN)
  // session.coreId — raw CorePass identifier
});
```

## Custom Session Store

The built-in `MemoryStore` works for single-process deployments. For production clusters, implement the `SessionStore` interface:

```ts
import type { SessionStore, StoreEntry } from '@tmmac/corepass-auth';

class RedisStore implements SessionStore {
  async set(key: string, value: StoreEntry, ttlMs: number): Promise<void> {
    await redis.set(key, JSON.stringify(value), 'PX', ttlMs);
  }

  async get(key: string): Promise<StoreEntry | null> {
    const raw = await redis.get(key);
    return raw ? JSON.parse(raw) : null;
  }

  async delete(key: string): Promise<void> {
    await redis.del(key);
  }
}
```

## Passkey / KYC Verification

Verify Ed448-signed data payloads from CorePass (e.g., KYC credentials):

```ts
const auth = corepassAuth({
  baseUrl: 'https://your-app.com',
  passkey: { enabled: true },
});
```

```bash
curl -X POST https://your-app.com/auth/passkey/data \
  -H "Content-Type: application/json" \
  -H "X-Signature: <ed448-signature>" \
  -H "X-Public-Key: <public-key>" \
  -d '{"coreId": "CB...", "credentialId": "...", "timestamp": "1710700000000000"}'
```

Timestamps are in **microseconds** (Unix epoch). The server validates the signature, checks for replays, and enforces a configurable time window.

## Exported Utilities

For advanced use cases, low-level functions are available:

```ts
import {
  // ICAN helpers
  validateIcan, normalizeIcan, isIcanAllowed,
  // Crypto
  verifyEd448Signature, extractPublicKeyFromHeader, canonicalJson,
  verifyPasskeyData,
  // QR generation
  generateQrDataUrl, generateQrSvg,
  // Store
  MemoryStore,
} from '@tmmac/corepass-auth';
```

## Security

- Challenge IDs are cryptographically random (UUIDs)
- Sessions expire automatically (configurable TTL)
- MemoryStore enforces a 50k entry limit to prevent DoS
- Passkey endpoint includes replay protection (signature deduplication)
- Timestamps are validated to be in the past (with 30s clock-skew leeway)
- Hook errors return sanitized messages to clients — details stay server-side
- No secrets stored client-side — all verification happens on the server

## Requirements

- **Node.js** >= 18
- **Express** 4.x or 5.x (peer dependency)
- **@noble/curves** (optional — only if `verifySignature: true` or `passkey.enabled`)
- **qrcode** (optional — only if `generateQr: true`)

## Development

```bash
npm install
npm run build       # ESM + CJS + Widget
npm test            # Vitest (67 tests)
npm run test:watch  # Watch mode
npm run dev         # TypeScript watch
```

## Project Structure

```
src/
├── index.ts              # Public API + config resolution
├── router.ts             # Express router (all endpoints)
├── challenge.ts          # Challenge CRUD
├── session.ts            # Session CRUD + token extraction
├── qr.ts                 # QR code generation (optional)
├── types.ts              # All TypeScript types
├── crypto/
│   ├── ican.ts           # ICAN validation + normalization
│   ├── ed448.ts          # Ed448 signature verification
│   └── passkey.ts        # Passkey/KYC data verification
├── stores/
│   └── memory.ts         # Default in-memory store
└── widget/
    ├── widget.ts         # Frontend widget (auto device detection)
    ├── mobile.ts         # Mobile redirect HTML
    └── styles.ts         # Widget CSS
```

## License

MIT
