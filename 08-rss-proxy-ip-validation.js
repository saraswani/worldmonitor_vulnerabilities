/**
 * Finding #08: RSS Proxy Domain-Name-Only Check Without Resolved-IP Validation (CWE-918)
 * Severity: Low-Medium | CVSS v3.1: 4.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N)
 * Category: Input validation / SSRF prevention
 *
 * WHAT WAS WRONG:
 * In api/rss-proxy.js (fetch line 126, redirect check line 236, isAllowedDomain line 288), the proxy
 * verified that the request hostname matched one of ~428 allowlisted domains, but never resolved the
 * hostname to its underlying IP address to verify that it does not point to internal/private subnets.
 * If an allowlisted domain expires, is hijacked, or resolves via internal DNS / hosts mapping to loopback,
 * the proxy could be leveraged for SSRF against internal localhost services or cloud metadata endpoints.
 * (The MCP proxy already rejected private IPs, but rss-proxy.js did not).
 *
 * WHAT THIS FIX DOES:
 * 1. Implements a robust DNS resolution and IP validation helper (IPv4 and IPv6).
 * 2. Rejects loopback (127.0.0.0/8, ::1), private RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 *    link-local / metadata (169.254.0.0/16, fe80::/10), unique local (fc00::/7), and broadcast addresses.
 * 3. Applies IP validation prior to initial socket connection and upon every HTTP redirect hop.
 *
 * ASSUMPTIONS:
 * - Node.js environment utilizing standard `dns/promises` and `net` modules.
 */

const dns = require('dns/promises');
const net = require('net');

// ============================================================================
// BEFORE (Vulnerable Pattern):
// if (isAllowedDomain(parsedUrl.hostname)) {
//   return fetch(targetUrl); // Resolves directly via OS resolver without IP inspection
// }
// ============================================================================

// AFTER (Remediated Pattern):

/**
 * Checks whether an IPv4 or IPv6 address belongs to private/reserved/internal IP ranges.
 */
function isPrivateOrReservedIp(ip) {
  if (!net.isIP(ip)) return true; // Reject invalid IPs

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    // 0.0.0.0/8 (Current network)
    if (parts[0] === 0) return true;
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 169.254.0.0/16 (Link-Local & Cloud Metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (parts[0] >= 224) return true;
    return false;
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    // ::1 (Loopback)
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
    // :: (Unspecified)
    if (normalized === '::') return true;
    // fc00::/7 (Unique Local Address)
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    // fe80::/10 (Link-Local)
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
    // IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if (normalized.startsWith('::ffff:')) {
      const v4Part = normalized.slice(7);
      return isPrivateOrReservedIp(v4Part);
    }
    return false;
  }

  return true;
}

/**
 * Validates a target URL: checks domain allowlist AND resolves DNS to ensure all IPs are public.
 * @param {string} urlString
 * @param {function} isAllowedDomain - Existing domain allowlist check function
 * @returns {Promise<{ allowed: boolean, reason?: string, resolvedIp?: string }>}
 */
async function validateSafeProxyTarget(urlString, isAllowedDomain) {
  let parsedUrl;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    return { allowed: false, reason: 'Invalid URL structure' };
  }

  // Enforce HTTPS or HTTP scheme
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return { allowed: false, reason: 'Unsupported protocol scheme' };
  }

  // 1. Verify hostname against domain allowlist
  if (!isAllowedDomain(parsedUrl.hostname)) {
    return { allowed: false, reason: 'Domain not permitted in proxy allowlist' };
  }

  // 2. Resolve DNS to verify underlying IP addresses
  try {
    const lookupResults = await dns.lookup(parsedUrl.hostname, { all: true });
    if (!lookupResults || lookupResults.length === 0) {
      return { allowed: false, reason: 'DNS resolution returned no records' };
    }

    for (const record of lookupResults) {
      if (isPrivateOrReservedIp(record.address)) {
        return {
          allowed: false,
          reason: `Resolved IP (${record.address}) is a private or reserved network address`,
        };
      }
    }

    return { allowed: true, resolvedIp: lookupResults[0].address };
  } catch (err) {
    return { allowed: false, reason: `DNS lookup failed: ${err.message}` };
  }
}

/**
 * Fetch wrapper that validates safety before initial fetch and on each redirect hop.
 */
async function safeProxyFetch(targetUrl, isAllowedDomain, options = {}, maxRedirects = 3) {
  let currentUrl = targetUrl;
  let redirectsRemaining = maxRedirects;

  while (redirectsRemaining >= 0) {
    const validation = await validateSafeProxyTarget(currentUrl, isAllowedDomain);
    if (!validation.allowed) {
      throw new Error(`SSRF Prevention Blocked Request: ${validation.reason}`);
    }

    const response = await fetch(currentUrl, { ...options, redirect: 'manual' });

    // Handle redirects manually to validate destination IP on every hop
    if (response.status >= 300 && response.status < 400 && response.headers.has('location')) {
      const redirectLocation = response.headers.get('location');
      currentUrl = new URL(redirectLocation, currentUrl).toString();
      redirectsRemaining--;
      continue;
    }

    return response;
  }

  throw new Error('Maximum redirect hops exceeded');
}

module.exports = {
  isPrivateOrReservedIp,
  validateSafeProxyTarget,
  safeProxyFetch,
};
