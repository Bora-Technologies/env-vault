const fs = require('fs');
const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const { unlockVault } = require('../lib/unlock');
const inquirer = require('inquirer');

/**
 * Parse .env content into key-value object
 */
function parseEnv(content) {
  const result = {};
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex > 0) {
      const key = trimmed.substring(0, eqIndex).trim();
      const value = trimmed.substring(eqIndex + 1);
      result[key] = value;
    }
  }
  return result;
}

/**
 * Convert key-value object back to .env format
 */
function stringifyEnv(obj) {
  return Object.entries(obj)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n') + '\n';
}

async function get(repoName, outputFile, options = {}) {
  // Determine if using local or central storage
  const useLocal = options.local || repoName === '.' || vault.hasLocalVault();

  if (useLocal) {
    // Use local .env-vault/ in current directory
    if (!vault.hasLocalVault()) {
      console.error('No .env-vault found in this directory.');
      console.error('Run: env-vault init-repo');
      process.exit(1);
    }
  } else {
    // Use central vault
    if (!vault.repoExists(repoName)) {
      console.error(`Repository "${repoName}" not found`);
      process.exit(1);
    }
  }

  // Unlock vault to get private key
  const privateKey = await unlockVault();
  const publicKey = vault.loadPublicKey();
  const fingerprint = crypto.getFingerprint(publicKey);

  // Load recipients
  const { recipients } = useLocal
    ? vault.loadLocalRecipients()
    : vault.loadRecipients(repoName);

  // Find our wrapped DEK
  const recipientData = recipients[fingerprint];
  if (!recipientData) {
    const name = useLocal ? vault.getRepoNameFromDir() : repoName;
    console.error(`You don't have access to "${name}"`);
    console.error('Ask the owner to share it with you using: env-vault share');
    process.exit(1);
  }

  // Unwrap the DEK
  const wrappedDEK = Buffer.from(recipientData.wrappedDEK, 'base64');
  let dek;
  try {
    dek = crypto.openBox(wrappedDEK, privateKey);
  } catch (err) {
    console.error('Failed to decrypt DEK. The data may be corrupted.');
    process.exit(1);
  }

  // Load and decrypt secrets
  const encryptedSecrets = useLocal
    ? vault.loadLocalSecrets()
    : vault.loadSecrets(repoName);

  let decrypted;
  try {
    decrypted = crypto.decrypt(encryptedSecrets, dek);
  } catch (err) {
    console.error('Failed to decrypt secrets. The data may be corrupted.');
    process.exit(1);
  }

  const content = decrypted.toString('utf8');

  // Determine output behavior
  let targetFile = outputFile;
  const shouldPrint = options.print;

  // Default to .env if no file specified and not printing
  if (!targetFile && !shouldPrint) {
    targetFile = '.env';
  }

  // Output
  if (targetFile) {
    // Check if file already exists
    if (fs.existsSync(targetFile)) {
      const existingContent = fs.readFileSync(targetFile, 'utf8');

      const { action } = await inquirer.prompt([
        {
          type: 'list',
          name: 'action',
          message: `${targetFile} already exists. What would you like to do?`,
          choices: [
            { name: 'Replace - Overwrite the existing file completely', value: 'replace' },
            { name: 'Merge - Add new keys and update existing ones', value: 'merge' },
            { name: 'Cancel - Keep existing file unchanged', value: 'cancel' }
          ]
        }
      ]);

      if (action === 'cancel') {
        console.log('Cancelled. File unchanged.');
        return;
      }

      if (action === 'merge') {
        const existingEnv = parseEnv(existingContent);
        const newEnv = parseEnv(content);

        // Count changes
        let added = 0;
        let updated = 0;

        for (const [key, value] of Object.entries(newEnv)) {
          if (!(key in existingEnv)) {
            added++;
          } else if (existingEnv[key] !== value) {
            updated++;
          }
          existingEnv[key] = value;
        }

        const mergedContent = stringifyEnv(existingEnv);
        fs.writeFileSync(targetFile, mergedContent);
        console.log(`Merged into ${targetFile} (${added} added, ${updated} updated)`);
        return;
      }
    }

    // Replace or new file
    fs.writeFileSync(targetFile, content);
    console.log(`Secrets written to ${targetFile}`);
  } else {
    process.stdout.write(content);
  }
}

module.exports = get;
