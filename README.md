# @tmmac/corepass-auth

Wiederverwendbares Express.js Middleware-Modul fuer [CorePass](https://corepass.net) Authentifizierung. QR-Code Login auf Desktop, Deep Link auf Mobile — eine Zeile Integration.

## Features

- **Desktop:** QR-Code scannen mit CorePass App + Polling
- **Mobile:** Deep Link oeffnet CorePass direkt + Client-Side Relay mit QR-Fallback
- **Passkey/KYC:** Opt-in Endpoint zur Verifikation Ed448-signierter Daten-Payloads
- **Pre-Auth Hook:** `onBeforeAuthenticate` fuer Custom-Validierung (Blocklists, Rate-Limiting)
- **Audit Logger:** Strukturiertes Login-Audit (IP, User-Agent, Result, Reason)
- **Frontend Widget:** Auto-Device-Detection, einbettbar via `<script>` Tag
- **Pluggbarer Store:** Default MemoryStore, austauschbar gegen Redis/DB
- **Dual Build:** ESM + CJS + Widget IIFE Bundle
- **Ed448 Signatur-Verifikation** (optional, via `@noble/curves`)
- **ICAN-Whitelist** und Payload-Normalisierung (`coreId`/`coreID`, `session`/`sessionId`)

## Installation

```bash
npm install @tmmac/corepass-auth
```

Express ist eine Peer-Dependency:

```bash
npm install express
```

Optionale Dependencies fuer erweiterte Features:

```bash
npm install @noble/curves  # Ed448 Signatur-Verifikation
npm install qrcode         # Server-seitige QR-Generierung
```

## Quick Start

```js
const express = require('express');
const { corepassAuth } = require('@tmmac/corepass-auth');

const app = express();
app.use(express.json());

const auth = corepassAuth({
  baseUrl: 'https://myapp.example.com',
  allowedIcans: ['CB1234567890ABCDEF1234567890ABCDEF1234567890'],
  icanNames: {
    'CB1234567890ABCDEF1234567890ABCDEF1234567890': 'Alice',
  },
});

// Auth-Routen mounten
app.use('/auth', auth.router);

// Geschuetzte Routen
app.get('/api/data', auth.requireAuth, (req, res) => {
  const session = req.corepassSession;
  res.json({ user: session.name, ican: session.ican });
});

app.listen(3000);
```

## Endpoints

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `POST` | `/challenge` | Neue Login-Challenge erstellen |
| `POST` | `/callback` | CorePass Callback nach QR-Scan |
| `GET` | `/app-link` | Mobile Redirect-Callback (type=app-link) |
| `GET` | `/challenge/:id` | Challenge-Status pollen |
| `GET` | `/session` | Aktuelle Session abfragen |
| `POST` | `/logout` | Session zerstoeren |
| `GET` | `/widget.js` | Frontend Widget (IIFE Bundle) |
| `GET` | `/mobile-redirect` | Intermediate Page fuer Mobile Deep Link |
| `POST` | `/passkey/data` | Signierte Daten verifizieren (opt-in) |

## Konfiguration

```ts
const auth = corepassAuth({
  // Pflicht
  baseUrl: 'https://myapp.example.com',

  // Optional: ICAN-Whitelist (leer = alle erlaubt)
  allowedIcans: ['CB...'],

  // Optional: ICAN -> Anzeigename
  icanNames: { 'CB...': 'Alice' },

  // Optional: Session-Einstellungen
  session: {
    ttl: 24 * 60 * 60 * 1000,         // App-Session TTL (default: 24h)
    challengeTtl: 5 * 60 * 1000,       // Challenge TTL (default: 5min)
  },

  // Optional: Ed448 Signatur-Verifikation
  verifySignature: false,

  // Optional: Server-seitige QR-Generierung (braucht 'qrcode' Paket)
  generateQr: false,

  // Optional: Eigener Session-Store
  store: new CustomStore(),

  // Optional: Callback nach erfolgreicher Authentifizierung
  onAuthenticated: async (session) => {
    console.log(`Logged in: ${session.name}`);
  },

  // Optional: Pre-Auth Hook — throw = Login ablehnen
  onBeforeAuthenticate: async (payload, challenge) => {
    if (isBlocked(payload.coreId)) {
      throw new Error('Account gesperrt');
    }
  },

  // Optional: Audit-Logging
  auditLogger: {
    log: async (event) => {
      // event: { type, userId, ip, userAgent, timestamp, reason? }
      await db.auditLog.create({ data: event });
    },
  },

  // Optional: Passkey/KYC Daten-Verifikation
  passkey: {
    enabled: true,
    path: '/passkey/data',              // Default
    timestampWindowMs: 10 * 60 * 1000,  // Default: 10min
  },
});
```

## Frontend Widget

Das Widget erkennt automatisch ob Desktop oder Mobile und zeigt den passenden Login-Flow:

```html
<div id="corepass-login"></div>
<script src="/auth/widget.js"></script>
<script>
  CorePassWidget.init({
    container: '#corepass-login',
    authBase: '/auth',
    onSuccess: (data) => {
      // data: { token, ican, name }
      window.location.href = '/dashboard';
    },
  });
</script>
```

## Custom Session Store

Der Default `MemoryStore` ist fuer Entwicklung und Single-Instance Deployments geeignet. Fuer Production mit mehreren Instanzen kann ein eigener Store implementiert werden:

```ts
import type { SessionStore, StoreEntry } from '@tmmac/corepass-auth';

class RedisStore implements SessionStore {
  async set(key: string, value: StoreEntry, ttlMs: number): Promise<void> { /* ... */ }
  async get(key: string): Promise<StoreEntry | null> { /* ... */ }
  async delete(key: string): Promise<void> { /* ... */ }
  async cleanup?(): Promise<void> { /* ... */ }
}
```

## Auth Flow

```
Desktop:                              Mobile:
┌──────────┐                          ┌──────────┐
│  Browser  │                          │  Browser  │
│  zeigt QR │                          │  oeffnet  │
│           │                          │ Deep Link │
└─────┬─────┘                          └─────┬─────┘
      │ scannt                               │
┌─────▼─────┐                          ┌─────▼─────┐
│  CorePass  │                          │  CorePass  │
│    App     │                          │    App     │
└─────┬─────┘                          └─────┬─────┘
      │ POST /callback                       │ GET /app-link
┌─────▼─────┐                          ┌─────▼─────┐
│   Server   │                          │   Server   │
│ verifiziert│                          │ verifiziert│
│ + Session  │                          │ + Redirect │
└─────┬─────┘                          └─────┬─────┘
      │ Poll: GET /challenge/:id             │ ?token=...
┌─────▼─────┐                          ┌─────▼─────┐
│  Browser   │                          │  Browser   │
│ eingeloggt │                          │ eingeloggt │
└────────────┘                          └────────────┘
```

## Exports

```ts
// Hauptfunktion
import { corepassAuth } from '@tmmac/corepass-auth';

// Typen
import type {
  CorePassAuthConfig, CorePassAuth, SessionData, SessionStore,
  StoreEntry, PasskeyConfig, PasskeyData, PasskeyResult,
  AuditEvent, AuditLogger, CallbackPayload,
  ChallengeResponse, ChallengeData,
} from '@tmmac/corepass-auth';

// Utilities
import {
  MemoryStore,
  validateIcan, normalizeIcan, isIcanAllowed,
  verifyEd448Signature, extractPublicKeyFromHeader, canonicalJson,
  verifyPasskeyData,
  generateQrDataUrl, generateQrSvg,
} from '@tmmac/corepass-auth';
```

## Development

```bash
npm install
npm run build       # ESM + CJS + Widget
npm test            # Vitest (67 Tests)
npm run test:watch  # Watch-Modus
npm run dev         # TypeScript Watch
```

## Projektstruktur

```
src/
├── index.ts              # Public API + Config-Resolution
├── router.ts             # Express Router (alle Endpoints)
├── challenge.ts          # Challenge CRUD
├── session.ts            # Session CRUD + Token-Extraktion
├── qr.ts                 # QR-Code Generierung (optional)
├── types.ts              # Alle TypeScript-Typen
├── crypto/
│   ├── ican.ts           # ICAN-Validierung + Normalisierung
│   ├── ed448.ts          # Ed448 Signatur-Verifikation
│   └── passkey.ts        # Passkey/KYC Daten-Verifikation
├── stores/
│   └── memory.ts         # Default In-Memory Store
└── widget/
    ├── widget.ts         # Frontend Widget (Auto-Device-Detection)
    ├── mobile.ts         # Mobile Redirect HTML
    └── styles.ts         # Widget CSS
```

## Lizenz

MIT
