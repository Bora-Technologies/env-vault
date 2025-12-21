const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits - recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits

/**
 * Encrypt data using AES-256-GCM
 * @param {Buffer|string} plaintext - Data to encrypt
 * @param {Buffer} key - 32-byte encryption key
 * @returns {Buffer} - IV (12 bytes) + ciphertext + auth tag (16 bytes)
 */
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: IV + ciphertext + authTag
  return Buffer.concat([iv, encrypted, authTag]);
}

/**
 * Decrypt data using AES-256-GCM
 * @param {Buffer} ciphertext - IV + encrypted data + auth tag
 * @param {Buffer} key - 32-byte encryption key
 * @returns {Buffer} - Decrypted data
 * @throws {Error} - If decryption or authentication fails
 */
function decrypt(ciphertext, key) {
  if (ciphertext.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Invalid ciphertext: too short');
  }

  const iv = ciphertext.subarray(0, IV_LENGTH);
  const authTag = ciphertext.subarray(ciphertext.length - AUTH_TAG_LENGTH);
  const encrypted = ciphertext.subarray(IV_LENGTH, ciphertext.length - AUTH_TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * Generate a random 256-bit key (DEK - Data Encryption Key)
 * @returns {Buffer} - 32-byte random key
 */
function generateKey() {
  return crypto.randomBytes(32);
}

module.exports = {
  encrypt,
  decrypt,
  generateKey,
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH
};
