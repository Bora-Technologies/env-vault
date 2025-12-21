const crypto = require('@env-vault/crypto');
const vault = require('./vault');
const inquirer = require('inquirer');

/**
 * Prompt for password and decrypt the private key
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

  try {
    const { encryptedKey, salt } = vault.loadPrivateKey();
    const derivedKey = await crypto.deriveKey(password, salt);
    const privateKey = crypto.decrypt(encryptedKey, derivedKey);
    return privateKey;
  } catch (err) {
    console.error('Failed to unlock vault. Wrong password?');
    process.exit(1);
  }
}

module.exports = { unlockVault };
