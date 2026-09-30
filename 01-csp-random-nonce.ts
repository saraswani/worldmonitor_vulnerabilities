/**
 * Finding #01: Static Hardcoded CSP Script Nonce (CWE-330)
 * Severity: Medium | CVSS v3.1: 5.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
 * Category: Client-side controls
 *
 * WHAT WAS WRONG:
 * The Content Security Policy script nonce was hardcoded as the fixed string
 * "wm-static-bootstrap" inside vercel.json and mirrored statically in index.html.
 * Because the nonce never changed across requests or sessions, an attacker could
 * bypass CSP script execution restrictions by simply adding nonce="wm-static-bootstrap"
 * to any injected script tag.
 *
 * WHAT THIS FIX DOES:
 * Generates a cryptographically random, base64-encoded nonce per request in Vercel Edge
 * Middleware (or Next.js middleware), builds a dynamic CSP header containing 'nonce-<value>'
 * with 'strict-dynamic', and passes the nonce to downstream renderers via request headers
 * (x-nonce) so script tags can dynamically bind the per-request nonce.
 *
 * ASSUMPTIONS:
 * - Runs in Edge Runtime (Vercel Edge Middleware / Web standard crypto).
 */

// ============================================================================
// BEFORE (Vulnerable Pattern - vercel.json / static header):
// "Content-Security-Policy": "script-src 'nonce-wm-static-bootstrap' 'strict-dynamic' https: 'unsafe-inline'; ..."
// ============================================================================

// AFTER (Remediated Edge Middleware Pattern):

export interface MiddlewareRequest {
  headers: Headers;
  url: string;
}

export interface MiddlewareResponse {
  headers: Headers;
}

/**
 * Generate a cryptographically secure, random 128-bit base64 nonce.
 */
export function generateCspNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

/**
 * Build dynamic Content Security Policy with random nonce and strict-dynamic.
 */
export function buildContentSecurityPolicy(nonce: string): string {
  return [
    `default-src 'self'`,
    `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline'`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' https: data: blob:`,
    `connect-src 'self' https://api.worldmonitor.app wss://api.worldmonitor.app https://*.ingest.sentry.io`,
    `font-src 'self' data:`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
  ].join('; ');
}

/**
 * Middleware handler attaching dynamic CSP headers and forwarding nonce.
 */
export function middleware(request: Request): Response {
  const nonce = generateCspNonce();
  const cspHeader = buildContentSecurityPolicy(nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeader);

  const response = new Response(null, {
    headers: {
      'Content-Security-Policy': cspHeader,
      'x-nonce': nonce,
    },
  });

  return response;
}
