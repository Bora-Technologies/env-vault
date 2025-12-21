const kdf = require('./kdf');
const aes = require('./aes');
const x25519 = require('./x25519');

module.exports = {
  // Key derivation (Argon2id)
  deriveKey: kdf.deriveKey,
  generateSalt: kdf.generateSalt,

  // AES-256-GCM encryption
  encrypt: aes.encrypt,
  decrypt: aes.decrypt,
  generateDEK: aes.generateKey,

  // X25519 key wrapping
  generateKeypair: x25519.generateKeypair,
  sealBox: x25519.sealBox,
  openBox: x25519.openBox,
  getFingerprint: x25519.getFingerprint,
  encodePublicKey: x25519.encodePublicKey,
  decodePublicKey: x25519.decodePublicKey,

  // Constants
  PUBLIC_KEY_LENGTH: x25519.PUBLIC_KEY_LENGTH,
  SECRET_KEY_LENGTH: x25519.SECRET_KEY_LENGTH
};
