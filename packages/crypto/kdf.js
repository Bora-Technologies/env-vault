const argon2 = require('argon2');

// Argon2id parameters (OWASP recommended)
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32 // 256 bits
};

/**
 * Derive a 256-bit key from a password using Argon2id
 * @param {string} password - The password to derive from
 * @param {Buffer} salt - 16-byte salt
 * @returns {Promise<Buffer>} - 32-byte derived key
 */
async function deriveKey(password, salt) {
  const hash = await argon2.hash(password, {
    ...ARGON2_CONFIG,
    salt,
    raw: true
  });
  return hash;
}

/**
 * Generate a random salt for key derivation
 * @returns {Buffer} - 16-byte random salt
 */
function generateSalt() {
  const crypto = require('crypto');
  return crypto.randomBytes(16);
}

module.exports = {
  deriveKey,
  generateSalt,
  ARGON2_CONFIG
};
