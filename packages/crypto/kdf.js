const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

// Scrypt parameters - hardened for secrets protection
// OWASP recommends N >= 2^17 for interactive, 2^20 for sensitive
// Using 2^17 (131072) as balance between security and UX (~1-2 sec on modern hardware)
const SCRYPT_CONFIG = {
  N: 131072,     // CPU/memory cost (2^17) - hardened from 2^14
  r: 8,          // Block size
  p: 1,          // Parallelization
  keyLength: 32  // 256 bits
};

// Legacy config for reading old vaults (migration support)
const SCRYPT_CONFIG_LEGACY = {
  N: 16384,      // Old 2^14 setting
  r: 8,
  p: 1,
  keyLength: 32
};

/**
 * Derive a 256-bit key from a password using scrypt (hardened parameters)
 * @param {string} password - The password to derive from
 * @param {Buffer} salt - 16-byte salt
 * @param {object} [config] - Optional config override (for legacy support)
 * @returns {Promise<Buffer>} - 32-byte derived key
 */
async function deriveKey(password, salt, config = SCRYPT_CONFIG) {
  // Calculate memory requirement: N * r * 128 bytes
  // N=131072, r=8 needs ~134MB, so we set maxmem to 256MB for safety
  const maxmem = 256 * 1024 * 1024;  // 256 MB

  const key = await scryptAsync(password, salt, config.keyLength, {
    N: config.N,
    r: config.r,
    p: config.p,
    maxmem: maxmem
  });
  return key;
}

/**
 * Derive key using legacy (weaker) parameters
 * Used for reading vaults created before security hardening
 * @param {string} password - The password to derive from
 * @param {Buffer} salt - 16-byte salt
 * @returns {Promise<Buffer>} - 32-byte derived key
 */
async function deriveKeyLegacy(password, salt) {
  return deriveKey(password, salt, SCRYPT_CONFIG_LEGACY);
}

/**
 * Generate a random salt for key derivation
 * @returns {Buffer} - 16-byte random salt
 */
function generateSalt() {
  return crypto.randomBytes(16);
}

module.exports = {
  deriveKey,
  deriveKeyLegacy,
  generateSalt,
  SCRYPT_CONFIG,
  SCRYPT_CONFIG_LEGACY
};
