const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const inquirer = require('inquirer');
const os = require('os');

async function init(label) {
  // Check if already initialized
  if (vault.isInitialized()) {
    console.log('Vault already initialized at ~/.env-vault');
    console.log('Use "env-vault identity show" to view your public key.');
    return;
  }

  console.log('Initializing env-vault...\n');

  // Prompt for device label if not provided
  let deviceLabel = label;
  if (!deviceLabel) {
    const { inputLabel } = await inquirer.prompt([
      {
        type: 'input',
        name: 'inputLabel',
        message: 'Label for this device (e.g., "MacBook Pro", "Work laptop"):',
        default: os.hostname()
      }
    ]);
    deviceLabel = inputLabel;
  }

  // Prompt for master password
  const { password, confirm } = await inquirer.prompt([
    {
      type: 'password',
      name: 'password',
      message: 'Enter master password:',
      mask: '*',
      validate: (input) => {
        if (input.length < 8) {
          return 'Password must be at least 8 characters';
        }
        return true;
      }
    },
    {
      type: 'password',
      name: 'confirm',
      message: 'Confirm master password:',
      mask: '*'
    }
  ]);

  if (password !== confirm) {
    console.error('Passwords do not match. Aborting.');
    process.exit(1);
  }

  console.log('\nGenerating keypair...');

  // Create vault directories
  vault.initDirs();

  // Generate keypair
  const keypair = crypto.generateKeypair();

  // Derive key from password
  const salt = crypto.generateSalt();
  const key = await crypto.deriveKey(password, salt);

  // Encrypt private key
  const encryptedPrivateKey = crypto.encrypt(keypair.secretKey, key);

  // Save to vault
  vault.savePrivateKey(encryptedPrivateKey, salt);
  vault.savePublicKey(keypair.publicKey);

  const fingerprint = crypto.getFingerprint(keypair.publicKey);

  vault.saveConfig({
    createdAt: new Date().toISOString(),
    deviceLabel: deviceLabel,
    fingerprint: fingerprint
  });

  const publicKeyB64 = crypto.encodePublicKey(keypair.publicKey);

  console.log('\nVault initialized successfully!');
  console.log(`\nDevice: ${deviceLabel}`);
  console.log(`Fingerprint: ${fingerprint}`);
  console.log('\nYour public key (share this with others to receive secrets):');
  console.log(`  ${publicKeyB64}`);
  console.log('\nVault location: ~/.env-vault');
}

module.exports = init;
