/**
 * Finding #07: Paid-Plan Rate Limits and Quotas Off by Default (CWE-1188)
 * Severity: Low-Medium | CVSS v3.1: 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)
 * Category: API security
 *
 * WHAT WAS WRONG:
 * In server/gateway.ts (line 2172), rate limit enforcement required `API_RATE_LIMIT_ENFORCE === "true"`
 * to actively throttle requests. In default deployments where this variable is unset or empty, the
 * system fell back to shadow mode (`rl_ceiling_shadow`), logging limits but allowing unrestricted request
 * volumes to paid endpoints.
 *
 * WHAT THIS FIX DOES:
 * 1. Switches rate limiting to "fail-secure / enforce-by-default": enforcement is active unless
 *    explicitly opted out via `API_RATE_LIMIT_ENFORCE === "false"`.
 * 2. Emits a high-priority startup warning to stdout/logger if shadow mode is intentionally configured.
 * 3. Applies consistent enforcement at all gateway checkpoint branches (gateway.ts lines 2226, 2257, 2291).
 *
 * ASSUMPTIONS:
 * - TypeScript / Node.js backend gateway service.
 */

// ============================================================================
// BEFORE (Vulnerable Pattern - server/gateway.ts:2172):
// const shouldEnforceRateLimit = process.env.API_RATE_LIMIT_ENFORCE === 'true'; // Disabled by default!
// ============================================================================

// AFTER (Remediated Pattern):

export interface RateLimitConfig {
  enforceRateLimit: boolean;
  isShadowMode: boolean;
}

/**
 * Parses rate limit enforcement configuration with fail-secure defaults.
 */
export function getRateLimitConfig(): RateLimitConfig {
  const envVal = process.env.API_RATE_LIMIT_ENFORCE?.trim().toLowerCase();

  // Enforce by default: Only opt out if explicitly set to 'false'
  const enforceRateLimit = envVal !== 'false';
  const isShadowMode = !enforceRateLimit;

  if (isShadowMode) {
    console.warn(
      '[SECURITY WARNING] API_RATE_LIMIT_ENFORCE is set to "false". ' +
      'Rate limits and tier quotas are operating in SHADOW MODE (logging only). ' +
      'Production deployments MUST NOT disable rate limiting.'
    );
  } else {
    console.info('[Security] Gateway rate limiting and quota enforcement: ACTIVE (enforced by default)');
  }

  return { enforceRateLimit, isShadowMode };
}

/**
 * Gatekeeper evaluation for gateway request dispatch (lines 2226, 2257, 2291).
 */
export function handleRateLimitEvaluation(
  isExceeded: boolean,
  currentUsage: number,
  tierAllowance: number,
  config: RateLimitConfig = getRateLimitConfig()
): { allowed: boolean; status: number; message?: string } {
  if (isExceeded) {
    if (config.enforceRateLimit) {
      return {
        allowed: false,
        status: 429,
        message: `Rate limit ceiling exceeded (${currentUsage}/${tierAllowance}). Upgrade tier or retry after reset window.`,
      };
    } else {
      // Shadow mode: log telemetry but pass through
      console.warn(`[rl_ceiling_shadow] Allowance exceeded: ${currentUsage}/${tierAllowance} (shadow mode enabled)`);
      return { allowed: true, status: 200 };
    }
  }

  return { allowed: true, status: 200 };
}
