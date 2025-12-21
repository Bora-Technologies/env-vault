const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

/**
 * Generate an X25519 keypair
 * @returns {{publicKey: Buffer, secretKey: Buffer}} - Keypair
 */
function generateKeypair() {
  const keypair = nacl.box.keyPair();
  return {
    publicKey: Buffer.from(keypair.publicKey),
    secretKey: Buffer.from(keypair.secretKey)
  };
}

/**
 * Seal a message for a recipient's public key (anonymous encryption)
 * Uses ephemeral keypair so sender identity is not revealed
 * @param {Buffer} message - Message to encrypt
 * @param {Buffer} recipientPublicKey - Recipient's X25519 public key
 * @returns {Buffer} - ephemeralPubKey (32) + nonce (24) + ciphertext
 */
function sealBox(message, recipientPublicKey) {
  // Generate ephemeral keypair for this message
  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  const encrypted = nacl.box(
    Uint8Array.from(message),
    nonce,
    Uint8Array.from(recipientPublicKey),
    ephemeral.secretKey
  );

  // Format: ephemeralPubKey + nonce + ciphertext
  return Buffer.concat([
    Buffer.from(ephemeral.publicKey),
    Buffer.from(nonce),
    Buffer.from(encrypted)
  ]);
}

/**
 * Open a sealed box using recipient's secret key
 * @param {Buffer} sealed - ephemeralPubKey + nonce + ciphertext
 * @param {Buffer} recipientSecretKey - Recipient's X25519 secret key
 * @returns {Buffer} - Decrypted message
 * @throws {Error} - If decryption fails
 */
function openBox(sealed, recipientSecretKey) {
  const ephemeralPubKeyLength = nacl.box.publicKeyLength; // 32
  const nonceLength = nacl.box.nonceLength; // 24

  if (sealed.length < ephemeralPubKeyLength + nonceLength + nacl.box.overheadLength) {
    throw new Error('Invalid sealed box: too short');
  }

  const ephemeralPubKey = sealed.subarray(0, ephemeralPubKeyLength);
  const nonce = sealed.subarray(ephemeralPubKeyLength, ephemeralPubKeyLength + nonceLength);
  const ciphertext = sealed.subarray(ephemeralPubKeyLength + nonceLength);

  const decrypted = nacl.box.open(
    Uint8Array.from(ciphertext),
    Uint8Array.from(nonce),
    Uint8Array.from(ephemeralPubKey),
    Uint8Array.from(recipientSecretKey)
  );

  if (!decrypted) {
    throw new Error('Decryption failed: invalid key or corrupted data');
  }

  return Buffer.from(decrypted);
}

/**
 * Get fingerprint of a public key (first 8 bytes of SHA-256, hex encoded)
 * @param {Buffer} publicKey - X25519 public key
 * @returns {string} - 16-character hex fingerprint
 */
function getFingerprint(publicKey) {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update(publicKey).digest();
  return hash.subarray(0, 8).toString('hex');
}

/**
 * Encode a public key as base64 for sharing
 * @param {Buffer} publicKey - X25519 public key
 * @returns {string} - Base64-encoded public key
 */
function encodePublicKey(publicKey) {
  return publicKey.toString('base64');
}

/**
 * Decode a base64 public key
 * @param {string} encoded - Base64-encoded public key
 * @returns {Buffer} - X25519 public key
 */
function decodePublicKey(encoded) {
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== nacl.box.publicKeyLength) {
    throw new Error(`Invalid public key: expected ${nacl.box.publicKeyLength} bytes, got ${key.length}`);
  }
  return key;
}

module.exports = {
  generateKeypair,
  sealBox,
  openBox,
  getFingerprint,
  encodePublicKey,
  decodePublicKey,
  PUBLIC_KEY_LENGTH: nacl.box.publicKeyLength,
  SECRET_KEY_LENGTH: nacl.box.secretKeyLength
};
