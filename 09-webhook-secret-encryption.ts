/**
 * Finding #09: Webhook Signing Secret Stored in Plaintext (CWE-312)
 * Severity: Low-Medium | CVSS v3.1: 4.2 (AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N)
 * Category: Data storage & privacy
 *
 * WHAT WAS WRONG:
 * In convex/schema.ts (notificationChannels table), the webhook variant wrapped the destination URL
 * inside an encrypted `webhookEnvelope`, but left `webhookSecret` stored as a plaintext `v.optional(v.string())`.
 * In the event of a database leak, read replica exposure, or backup compromise, stored HMAC signing
 * secrets could be harvested to forge alerts across downstream consumer webhooks.
 *
 * WHAT THIS FIX DOES:
 * 1. Implements AES-256-GCM authenticated envelope encryption helpers for webhook secrets.
 * 2. Provides safe encrypt-before-store and decrypt-on-use mutations.
 * 3. Provides a one-time migration and secret rotation sketch for legacy unencrypted records.
 *
 * ASSUMPTIONS:
 * - Convex backend with server-side environment key `WEBHOOK_ENCRYPTION_KEY` (32-byte hex/base64).
 */

import crypto from 'crypto';

// ============================================================================
// BEFORE (Vulnerable Pattern - convex/schema.ts):
// webhookVariant: {
//   webhookEnvelope: v.string(), // Encrypted payload
//   webhookSecret: v.optional(v.string()), // Plaintext secret!
// }
// ============================================================================

// AFTER (Remediated Pattern):

export interface EncryptedSecretEnvelope {
  encryptedData: string; // Base64 ciphertext
  iv: string;            // Base64 12-byte IV
  authTag: string;       // Base64 16-byte Auth Tag
  keyVersion: number;
}

const ALGORITHM = 'aes-256-gcm';
const KEY_VERSION = 1;

function getMasterKey(): Buffer {
  const keyHex = process.env.WEBHOOK_ENCRYPTION_KEY;
  if (!keyHex || keyHex.length < 64) {
    throw new Error('WEBHOOK_ENCRYPTION_KEY environment variable is not configured or too short (must be 32 bytes hex)');
  }
  return Buffer.from(keyHex.slice(0, 64), 'hex');
}

/**
 * Encrypts a webhook signing secret with AES-256-GCM before persisting to database.
 */
export function encryptWebhookSecret(plaintextSecret: string): EncryptedSecretEnvelope {
  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM

  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);
  let encrypted = cipher.update(plaintextSecret, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    keyVersion: KEY_VERSION,
  };
}

/**
 * Decrypts an encrypted webhook secret envelope for signing outbound notification payloads.
 */
export function decryptWebhookSecret(envelope: EncryptedSecretEnvelope): string {
  const masterKey = getMasterKey();
  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(envelope.encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Migration Sketch: Iterate legacy plaintext secrets, encrypt in place, and flag for rotation.
 */
export async function migrateLegacyWebhookSecrets(
  getAllChannels: () => Promise<Array<{ _id: string; webhookSecret?: string; webhookSecretEnvelope?: EncryptedSecretEnvelope }>>,
  updateChannel: (id: string, patch: { webhookSecret?: null; webhookSecretEnvelope: EncryptedSecretEnvelope }) => Promise<void>
) {
  const channels = await getAllChannels();
  for (const channel of channels) {
    if (channel.webhookSecret && !channel.webhookSecretEnvelope) {
      const envelope = encryptWebhookSecret(channel.webhookSecret);
      await updateChannel(channel._id, {
        webhookSecret: null, // Null out legacy plaintext field
        webhookSecretEnvelope: envelope,
      });
      console.log(`[Migration] Encrypted legacy secret for channel ${channel._id}`);
    }
  }
}
