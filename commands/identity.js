const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');

function show() {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  const publicKey = vault.loadPublicKey();
  const publicKeyB64 = crypto.encodePublicKey(publicKey);
  const fingerprint = crypto.getFingerprint(publicKey);

  console.log('Your public key (share this with others):');
  console.log(`  ${publicKeyB64}`);
  console.log(`\nFingerprint: ${fingerprint}`);
}

module.exports = { show };
