/**
 * Finding #06: Over-Privileged Static Enterprise Keys (CWE-798 / CWE-256)
 * Severity: Medium | CVSS v3.1: 5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)
 * Category: Authentication & session
 *
 * WHAT WAS WRONG:
 * Enterprise keys in `WORLDMONITOR_VALID_KEYS` were stored as a plaintext comma-separated list
 * and compared directly using standard string equality (unlike user keys which use SHA-256 hashes).
 * Enterprise keys bypassed all entitlement checks, granted unlimited tier 3 allowances, never expired,
 * and could be supplied via ambient browser cookies (`__Host-wm-pro-key`, `__Host-wm-widget-key`).
 *
 * WHAT THIS FIX DOES:
 * 1. Stores enterprise keys strictly as SHA-256 hashes with structured metadata (owner, expiresAt, revoked).
 * 2. Uses `crypto.timingSafeEqual` for constant-time comparison to prevent timing attacks.
 * 3. Enforces key expiration dates and revocation checks.
 * 4. Disallows enterprise key authentication via cookies (restricting key delivery to explicit headers).
 *
 * ASSUMPTIONS:
 * - Runs in Node.js / Vercel Serverless runtime with standard `crypto` module.
 */

const crypto = require('crypto');

// ============================================================================
// BEFORE (Vulnerable Pattern):
// function isValidEnterpriseKey(rawKey) {
//   const validKeys = (process.env.WORLDMONITOR_VALID_KEYS || '').split(',').map(k => k.trim());
//   return validKeys.includes(rawKey); // Plaintext match, no expiry, no owner
// }
// // Tester cookie extraction:
// const key = req.cookies['__Host-wm-pro-key'] || req.cookies['__Host-wm-widget-key'] || req.headers['x-worldmonitor-key'];
// ============================================================================

// AFTER (Remediated Pattern):

/**
 * Enterprise key definition with metadata.
 * In production, this can be loaded from secure config / KMS / Convex DB.
 * Format of WORLDMONITOR_ENTERPRISE_KEY_HASHES:
 * JSON string: [{"owner": "partner-a", "hash": "<sha256_hex>", "expiresAt": "2027-01-01T00:00:00Z", "revoked": false}]
 */
function loadEnterpriseKeyRegistry() {
  try {
    const raw = process.env.WORLDMONITOR_ENTERPRISE_KEY_HASHES || '[]';
    return JSON.parse(raw);
  } catch (err) {
    console.error('[Security] Failed to parse enterprise key registry', err);
    return [];
  }
}

/**
 * Hash raw key using SHA-256 for uniform comparison against registered hashes.
 */
function hashKey(rawKey) {
  return crypto.createHash('sha256').update(String(rawKey)).digest('hex');
}

/**
 * Validates enterprise key with SHA-256 hashing, timing-safe equality, expiry, and revocation checks.
 * @param {string} rawKey - Raw API key from Authorization or X-WorldMonitor-Key header.
 * @returns {{ valid: boolean, owner?: string, tier?: number }}
 */
function isValidEnterpriseKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string' || rawKey.length < 16) {
    return { valid: false };
  }

  const providedHashBuffer = Buffer.from(hashKey(rawKey), 'utf8');
  const registry = loadEnterpriseKeyRegistry();
  const now = Date.now();

  for (const entry of registry) {
    if (!entry.hash || entry.revoked) continue;

    // Check expiration timestamp if configured
    if (entry.expiresAt && new Date(entry.expiresAt).getTime() < now) {
      continue;
    }

    const registeredHashBuffer = Buffer.from(entry.hash, 'utf8');
    if (
      providedHashBuffer.length === registeredHashBuffer.length &&
      crypto.timingSafeEqual(providedHashBuffer, registeredHashBuffer)
    ) {
      return {
        valid: true,
        owner: entry.owner || 'enterprise-tenant',
        tier: 3,
        expiresAt: entry.expiresAt,
      };
    }
  }

  return { valid: false };
}

/**
 * Secure key extractor: ONLY extracts from explicit headers.
 * Enterprise keys must NEVER be accepted from ambient browser cookies.
 */
function extractApiKey(req) {
  // Reject cookie-based extraction for administrative / enterprise authorization
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return req.headers['x-worldmonitor-key'] || null;
}

module.exports = {
  isValidEnterpriseKey,
  extractApiKey,
  hashKey,
};
