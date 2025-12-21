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
            { name: 'Preview - See changes before merging', value: 'preview' },
            { name: 'Cancel - Keep existing file unchanged', value: 'cancel' }
          ]
        }
      ]);

      if (action === 'cancel') {
        console.log('Cancelled. File unchanged.');
        return;
      }

      const existingLines = existingContent.split('\n');
      const newEnv = parseEnv(content);
      const updates = {};
      const additions = {};

      // Analyze changes
      for (const [key, value] of Object.entries(newEnv)) {
        let found = false;
        // Check if key exists in current file
        for (const line of existingLines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('#')) continue;
          const eqIndex = trimmed.indexOf('=');
          if (eqIndex > 0) {
            const currentKey = trimmed.substring(0, eqIndex).trim();
            if (currentKey === key) {
              found = true;
              const currentValue = trimmed.substring(eqIndex + 1);
              if (currentValue !== value) {
                updates[key] = { old: currentValue, new: value };
              }
              break;
            }
          }
        }
        if (!found) {
          additions[key] = value;
        }
      }

      if (Object.keys(updates).length === 0 && Object.keys(additions).length === 0) {
        console.log('No changes needed. File is up to date.');
        return;
      }

      // Preview
      if (action === 'preview' || action === 'merge') {
        if (Object.keys(updates).length > 0) {
          console.log('\nUpdates:');
          for (const [key, change] of Object.entries(updates)) {
            console.log(`  ${key}: ${change.old} -> ${change.new}`);
          }
        }
        if (Object.keys(additions).length > 0) {
          console.log('\nAdditions:');
          for (const [key, value] of Object.entries(additions)) {
            console.log(`  + ${key}=${value}`);
          }
        }
        console.log();

        if (action === 'preview') {
          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: 'Apply these changes?',
              default: true
            }
          ]);
          if (!confirm) {
            console.log('Cancelled.');
            return;
          }
        }
      }

      // Apply merge preserving comments/structure
      const newLines = [];
      const appliedKeys = new Set();

      for (const line of existingLines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) {
          newLines.push(line);
          continue;
        }

        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
          const key = trimmed.substring(0, eqIndex).trim();
          if (newEnv[key] !== undefined) {
            newLines.push(`${key}=${newEnv[key]}`);
            appliedKeys.add(key);
            continue;
          }
        }
        newLines.push(line);
      }

      // Append additions
      for (const [key, value] of Object.entries(newEnv)) {
        if (!appliedKeys.has(key)) {
          newLines.push(`${key}=${value}`);
        }
      }

      fs.writeFileSync(targetFile, newLines.join('\n'));
      console.log(`Merged into ${targetFile}`);
      return;
    }

    // Replace or new file
    fs.writeFileSync(targetFile, content);
    console.log(`Secrets written to ${targetFile}`);
  } else {
    process.stdout.write(content);
  }
}

module.exports = get;
