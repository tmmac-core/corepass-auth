/**
 * CorePass Login Widget — self-contained IIFE bundle.
 * Handles: Device Detection → QR or Mobile → Polling → Session → App-Switch Recovery.
 *
 * Usage:
 *   <div id="corepass-login"></div>
 *   <script src="/auth/widget.js"></script>
 *   <script>
 *     CorePassWidget.init({
 *       container: '#corepass-login',
 *       authPath: '/auth',
 *       onSuccess: ({ token, ican, name }) => { ... },
 *       theme: 'dark',
 *       locale: 'de'
 *     });
 *   </script>
 */

import { WIDGET_CSS } from './styles.js';

interface WidgetConfig {
  container: string | HTMLElement;
  authPath?: string;
  onSuccess?: (data: { token: string; ican: string; name: string }) => void;
  onError?: (error: string) => void;
  theme?: 'dark' | 'light';
  locale?: 'de' | 'en';
  pollInterval?: number;
}

interface ChallengeResponse {
  challengeId: string;
  loginUri: string;
  mobileUri: string;
  qrDataUrl?: string;
  expiresIn: number;
}

const TEXTS = {
  de: {
    title: 'Mit CorePass anmelden',
    scanning: 'Warte auf CorePass...',
    openApp: 'CorePass oeffnen',
    expired: 'Sitzung abgelaufen',
    retry: 'Erneut versuchen',
    rejected: 'Zugang verweigert',
    error: 'Fehler beim Anmelden',
    scanQr: 'Scanne den QR-Code mit CorePass',
    orManual: 'Oder oeffne CorePass und scanne den Code',
  },
  en: {
    title: 'Sign in with CorePass',
    scanning: 'Waiting for CorePass...',
    openApp: 'Open CorePass',
    expired: 'Session expired',
    retry: 'Try again',
    rejected: 'Access denied',
    error: 'Login failed',
    scanQr: 'Scan the QR code with CorePass',
    orManual: 'Or open CorePass and scan the code',
  },
};

function isMobile(): boolean {
  return /Android|iPhone|iPad|iPod|Mobile|webOS|BlackBerry|Opera Mini|IEMobile/i.test(
    navigator.userAgent
  );
}

class CorePassWidgetInstance {
  private el: HTMLElement;
  private authPath: string;
  private config: WidgetConfig;
  private texts: typeof TEXTS.de;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private challengeId: string | null = null;
  private destroyed = false;

  constructor(config: WidgetConfig) {
    this.config = config;
    this.authPath = (config.authPath || '/auth').replace(/\/+$/, '');
    this.texts = TEXTS[config.locale || 'de'];

    // Resolve container
    const container = typeof config.container === 'string'
      ? document.querySelector(config.container)
      : config.container;
    if (!container) throw new Error(`CorePassWidget: Container not found: ${config.container}`);
    this.el = container as HTMLElement;

    // Inject CSS once
    if (!document.getElementById('cp-widget-css')) {
      const style = document.createElement('style');
      style.id = 'cp-widget-css';
      style.textContent = WIDGET_CSS;
      document.head.appendChild(style);
    }

    // Check for app-switch recovery (mobile returning from CorePass)
    const recovered = this.tryRecoverSession();
    if (!recovered) {
      this.start();
    }
  }

  /** Check sessionStorage for a pending challenge (mobile app-switch recovery) */
  private tryRecoverSession(): boolean {
    try {
      const stored = sessionStorage.getItem('cp_challengeId');
      if (stored) {
        sessionStorage.removeItem('cp_challengeId');
        this.challengeId = stored;
        this.renderPolling();
        this.startPolling();
        return true;
      }
    } catch {
      // sessionStorage not available
    }
    return false;
  }

  /** Start the login flow: create challenge, then show QR or mobile button */
  private async start(): Promise<void> {
    this.renderLoading();

    try {
      const res = await fetch(`${this.authPath}/challenge`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ChallengeResponse = await res.json();
      this.challengeId = data.challengeId;

      if (isMobile()) {
        this.renderMobile(data);
      } else {
        this.renderQr(data);
      }

      this.startPolling();
    } catch (err) {
      this.renderError(this.texts.error);
    }
  }

  // ===== Rendering =====

  private renderLoading(): void {
    const theme = this.config.theme || 'dark';
    this.el.innerHTML = `
      <div class="cp-widget cp-${theme}">
        <div class="cp-card">
          <div class="cp-title">${this.texts.title}</div>
          <div class="cp-status"><span class="cp-spinner"></span> Laden...</div>
        </div>
      </div>`;
  }

  private renderQr(data: ChallengeResponse): void {
    const theme = this.config.theme || 'dark';
    const qrHtml = data.qrDataUrl
      ? `<img src="${data.qrDataUrl}" alt="QR Code" width="200" height="200">`
      : `<canvas id="cp-qr-canvas" width="200" height="200"></canvas>`;

    this.el.innerHTML = `
      <div class="cp-widget cp-${theme}">
        <div class="cp-card">
          <div class="cp-title">${this.texts.title}</div>
          <div class="cp-qr-container">${qrHtml}</div>
          <div class="cp-status">
            <span class="cp-spinner"></span> ${this.texts.scanQr}
          </div>
        </div>
      </div>`;

    // Client-side QR generation if no server-side QR
    if (!data.qrDataUrl) {
      this.generateClientQr(data.loginUri);
    }
  }

  private renderMobile(data: ChallengeResponse): void {
    const theme = this.config.theme || 'dark';
    const redirectUrl = `${this.authPath}/mobile-redirect?challengeId=${data.challengeId}`;

    this.el.innerHTML = `
      <div class="cp-widget cp-${theme}">
        <div class="cp-card">
          <div class="cp-title">${this.texts.title}</div>
          <a class="cp-btn" id="cp-mobile-btn" href="${redirectUrl}">
            ${this.texts.openApp}
          </a>
          <div class="cp-status" style="margin-top:12px">
            <span class="cp-spinner"></span> ${this.texts.scanning}
          </div>
          <hr class="cp-divider">
          <div class="cp-fallback">${this.texts.orManual}</div>
        </div>
      </div>`;

    // Store challengeId for app-switch recovery
    try {
      sessionStorage.setItem('cp_challengeId', data.challengeId);
    } catch {
      // ignore
    }

    // Bind click handler
    const btn = document.getElementById('cp-mobile-btn');
    if (btn) {
      btn.addEventListener('click', () => {
        // Store challengeId before navigating away
        try {
          sessionStorage.setItem('cp_challengeId', data.challengeId);
        } catch {
          // ignore
        }
      });
    }
  }

  private renderPolling(): void {
    const theme = this.config.theme || 'dark';
    this.el.innerHTML = `
      <div class="cp-widget cp-${theme}">
        <div class="cp-card">
          <div class="cp-title">${this.texts.title}</div>
          <div class="cp-status">
            <span class="cp-spinner"></span> ${this.texts.scanning}
          </div>
        </div>
      </div>`;
  }

  private renderError(message: string): void {
    const theme = this.config.theme || 'dark';
    this.el.innerHTML = `
      <div class="cp-widget cp-${theme}">
        <div class="cp-card">
          <div class="cp-title">${this.texts.title}</div>
          <div class="cp-error">${message}</div>
          <button class="cp-retry" id="cp-retry-btn">${this.texts.retry}</button>
        </div>
      </div>`;

    const btn = document.getElementById('cp-retry-btn');
    if (btn) {
      btn.addEventListener('click', () => this.start());
    }
  }

  // ===== Polling =====

  private startPolling(): void {
    const interval = this.config.pollInterval || 2000;
    this.pollTimer = setInterval(() => this.poll(), interval);
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private async poll(): Promise<void> {
    if (this.destroyed || !this.challengeId) return;

    try {
      const res = await fetch(`${this.authPath}/challenge/${this.challengeId}`);
      if (!res.ok) {
        if (res.status === 404) {
          this.stopPolling();
          this.renderError(this.texts.expired);
        }
        return;
      }

      const data = await res.json();

      if (data.status === 'authenticated') {
        this.stopPolling();
        try { sessionStorage.removeItem('cp_challengeId'); } catch {}
        if (this.config.onSuccess) {
          this.config.onSuccess({
            token: data.token,
            ican: data.ican,
            name: data.name,
          });
        }
      } else if (data.status === 'rejected') {
        this.stopPolling();
        this.renderError(`${this.texts.rejected}: ${data.reason || ''}`);
      } else if (data.status === 'expired') {
        this.stopPolling();
        this.renderError(this.texts.expired);
      }
    } catch {
      // Network error — keep polling, might recover
    }
  }

  // ===== Client-side QR =====

  private generateClientQr(data: string): void {
    const canvas = document.getElementById('cp-qr-canvas') as HTMLCanvasElement | null;
    if (!canvas) return;

    // Minimal QR encoding using canvas — for production, a library like qrcode is better.
    // This is a fallback: we draw a placeholder and encourage server-side QR.
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Try loading qrcode library from CDN as last resort
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js';
    script.onload = () => {
      if ((window as any).QRCode) {
        (window as any).QRCode.toCanvas(canvas, data, {
          width: 200,
          margin: 1,
          color: { dark: '#000000', light: '#ffffff' },
        });
      }
    };
    script.onerror = () => {
      // Fallback: show the URI as text
      ctx.fillStyle = '#27272a';
      ctx.fillRect(0, 0, 200, 200);
      ctx.fillStyle = '#a1a1aa';
      ctx.font = '12px monospace';
      ctx.fillText('QR laden...', 50, 100);
    };
    document.head.appendChild(script);
  }

  /** Clean up timers and state */
  destroy(): void {
    this.destroyed = true;
    this.stopPolling();
    this.el.innerHTML = '';
  }
}

// ===== Global API (IIFE) =====

const CorePassWidget = {
  init(config: WidgetConfig): CorePassWidgetInstance {
    return new CorePassWidgetInstance(config);
  },
};

// Expose globally
(window as any).CorePassWidget = CorePassWidget;

export { CorePassWidget, CorePassWidgetInstance };
export type { WidgetConfig };
