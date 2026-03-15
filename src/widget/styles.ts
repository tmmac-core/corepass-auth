/** CorePass Login Widget CSS — injected into the page at runtime */
export const WIDGET_CSS = `
.cp-widget {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  max-width: 360px;
  margin: 0 auto;
  text-align: center;
}

.cp-widget * { box-sizing: border-box; margin: 0; padding: 0; }

/* Theme: dark */
.cp-widget.cp-dark {
  color: #e4e4e7;
}
.cp-widget.cp-dark .cp-card {
  background: #18181b;
  border: 1px solid #27272a;
}
.cp-widget.cp-dark .cp-btn {
  background: #f59e0b;
  color: #18181b;
}
.cp-widget.cp-dark .cp-btn:hover {
  background: #d97706;
}
.cp-widget.cp-dark .cp-status {
  color: #a1a1aa;
}

/* Theme: light */
.cp-widget.cp-light {
  color: #18181b;
}
.cp-widget.cp-light .cp-card {
  background: #ffffff;
  border: 1px solid #e4e4e7;
}
.cp-widget.cp-light .cp-btn {
  background: #f59e0b;
  color: #18181b;
}
.cp-widget.cp-light .cp-btn:hover {
  background: #d97706;
}
.cp-widget.cp-light .cp-status {
  color: #71717a;
}

.cp-card {
  border-radius: 12px;
  padding: 24px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.cp-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}

.cp-qr-container {
  display: flex;
  justify-content: center;
  margin: 16px 0;
}

.cp-qr-container canvas,
.cp-qr-container img {
  border-radius: 8px;
}

.cp-btn {
  display: inline-block;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: background 0.2s;
  width: 100%;
}

.cp-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.cp-status {
  font-size: 14px;
  margin-top: 12px;
}

.cp-spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: cp-spin 0.75s linear infinite;
  vertical-align: middle;
  margin-right: 6px;
}

@keyframes cp-spin {
  to { transform: rotate(360deg); }
}

.cp-error {
  color: #ef4444;
  font-size: 14px;
  margin-top: 8px;
}

.cp-retry {
  font-size: 13px;
  color: #f59e0b;
  cursor: pointer;
  background: none;
  border: none;
  text-decoration: underline;
  margin-top: 8px;
}

.cp-divider {
  margin: 16px 0;
  border: none;
  border-top: 1px solid #27272a;
}
.cp-light .cp-divider {
  border-color: #e4e4e7;
}

.cp-fallback {
  font-size: 13px;
  margin-top: 12px;
}
.cp-fallback a {
  color: #f59e0b;
}
`;
