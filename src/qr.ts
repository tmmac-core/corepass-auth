/**
 * Server-side QR code generation.
 * Requires: qrcode (optional dependency)
 */

let qrModule: any = null;

async function getQrModule(): Promise<typeof import('qrcode')> {
  if (qrModule) return qrModule;
  try {
    const mod = await import('qrcode');
    qrModule = mod.default || mod;
    return qrModule;
  } catch {
    throw new Error(
      'QR generation requires the qrcode package. Install with: npm install qrcode'
    );
  }
}

/** Generate a QR code as data URL (PNG base64) */
export async function generateQrDataUrl(data: string): Promise<string> {
  const qr = await getQrModule();
  return qr.toDataURL(data, {
    type: 'image/png',
    width: 256,
    margin: 1,
    color: { dark: '#000000', light: '#ffffff' },
  });
}

/** Generate a QR code as SVG string */
export async function generateQrSvg(data: string): Promise<string> {
  const qr = await getQrModule();
  return qr.toString(data, { type: 'svg', margin: 1 });
}
