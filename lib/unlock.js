const crypto = require('@env-vault/crypto');
const vault = require('./vault');
const inquirer = require('inquirer');

/**
 * Prompt for password and decrypt the private key
 * Supports both new (hardened) and legacy KDF parameters
 * @returns {Promise<Buffer>} - Decrypted private key
 */
async function unlockVault() {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  const { password } = await inquirer.prompt([
    {
      type: 'password',
      name: 'password',
      message: 'Enter master password:',
      mask: '*'
    }
  ]);

  const { encryptedKey, salt } = vault.loadPrivateKey();

  // Try with new hardened parameters first
  try {
    const derivedKey = await crypto.deriveKey(password, salt);
    const privateKey = crypto.decrypt(encryptedKey, derivedKey);
    return privateKey;
  } catch (err) {
    // Fall back to legacy parameters for old vaults
    try {
      const derivedKeyLegacy = await crypto.deriveKeyLegacy(password, salt);
      const privateKey = crypto.decrypt(encryptedKey, derivedKeyLegacy);

      // Warn user about legacy vault
      console.log('\nNote: Your vault uses older security parameters.');
      console.log('Run "env-vault upgrade" to strengthen encryption.\n');

      return privateKey;
    } catch (legacyErr) {
      console.error('Failed to unlock vault. Wrong password?');
      process.exit(1);
    }
  }
}

module.exports = { unlockVault };
