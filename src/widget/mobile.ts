/**
 * Mobile detection and redirect strategy.
 * Solves the URI re-encoding problem on mobile by using
 * an intermediate HTML page with <a href>.click().
 */

/** Detect if the user agent is a mobile device */
export function isMobileDevice(userAgent: string): boolean {
  return /Android|iPhone|iPad|iPod|Mobile|webOS|BlackBerry|Opera Mini|IEMobile/i.test(userAgent);
}

/** Detect if the user agent is iOS (special handling needed) */
export function isIOS(userAgent: string): boolean {
  return /iPhone|iPad|iPod/i.test(userAgent);
}

/**
 * Generate the intermediate redirect HTML page.
 * This page contains an <a href> with the corepass: URI.
 * Using <a>.click() bypasses the browser's URL re-encoding
 * that happens with window.location.href assignment.
 */
export function getMobileRedirectHtml(corepassUri: string): string {
  // Escape the URI for safe HTML attribute embedding
  const safeUri = escapeHtmlAttr(corepassUri);

  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CorePass Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #e4e4e7;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100svh;
      padding: 24px;
      text-align: center;
    }
    .container { max-width: 320px; }
    .spinner {
      width: 40px; height: 40px;
      border: 3px solid #27272a;
      border-top-color: #f59e0b;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 20px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    h2 { font-size: 18px; margin-bottom: 8px; }
    p { font-size: 14px; color: #a1a1aa; margin-bottom: 20px; }
    .btn {
      display: inline-block;
      padding: 14px 28px;
      background: #f59e0b;
      color: #18181b;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 16px;
      touch-action: manipulation;
    }
    .back {
      display: block;
      margin-top: 16px;
      color: #a1a1aa;
      font-size: 13px;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="spinner"></div>
    <h2>CorePass wird geoeffnet...</h2>
    <p>Falls die App nicht automatisch startet:</p>
    <a id="cplink" class="btn" href="${safeUri}">CorePass oeffnen</a>
    <a class="back" href="/">Zurueck zur Anmeldung</a>
  </div>
  <script>
    // Programmatic click on <a> element — browser passes the href
    // as a raw string to the OS handler WITHOUT re-encoding.
    // This is the key trick that fixes mobile deep links.
    setTimeout(function() {
      var link = document.getElementById('cplink');
      if (link) link.click();
    }, 200);
  </script>
</body>
</html>`;
}

/** Escape a string for safe use in HTML attributes */
function escapeHtmlAttr(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
