const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

// Scrypt parameters (secure defaults)
const SCRYPT_CONFIG = {
  N: 16384,      // CPU/memory cost (2^14)
  r: 8,          // Block size
  p: 1,          // Parallelization
  keyLength: 32  // 256 bits
};

/**
 * Derive a 256-bit key from a password using scrypt
 * @param {string} password - The password to derive from
 * @param {Buffer} salt - 16-byte salt
 * @returns {Promise<Buffer>} - 32-byte derived key
 */
async function deriveKey(password, salt) {
  const key = await scryptAsync(password, salt, SCRYPT_CONFIG.keyLength, {
    N: SCRYPT_CONFIG.N,
    r: SCRYPT_CONFIG.r,
    p: SCRYPT_CONFIG.p
  });
  return key;
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
  generateSalt,
  SCRYPT_CONFIG
};
