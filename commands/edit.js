const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const { unlockVault } = require('../lib/unlock');

async function edit(repoName) {
  if (!vault.repoExists(repoName)) {
    console.error(`Repository "${repoName}" not found`);
    process.exit(1);
  }

  // Unlock vault to get our private key
  const privateKey = await unlockVault();
  const publicKey = vault.loadPublicKey();
  const myFingerprint = crypto.getFingerprint(publicKey);

  // Load recipients
  const { dek_version, recipients } = vault.loadRecipients(repoName);

  // Find our wrapped DEK
  const myRecipientData = recipients[myFingerprint];
  if (!myRecipientData) {
    console.error(`You don't have access to "${repoName}"`);
    process.exit(1);
  }

  // Unwrap the DEK
  const wrappedDEK = Buffer.from(myRecipientData.wrappedDEK, 'base64');
  let dek;
  try {
    dek = crypto.openBox(wrappedDEK, privateKey);
  } catch (err) {
    console.error('Failed to decrypt DEK.');
    process.exit(1);
  }

  // Decrypt the secrets
  const encryptedSecrets = vault.loadSecrets(repoName);
  let content;
  try {
    content = crypto.decrypt(encryptedSecrets, dek).toString('utf8');
  } catch (err) {
    console.error('Failed to decrypt secrets.');
    process.exit(1);
  }

  // Create temp file
  const tempFile = path.join(os.tmpdir(), `env-vault-${repoName}-${Date.now()}.env`);
  fs.writeFileSync(tempFile, content, { mode: 0o600 });

  // Get editor
  const editor = process.env.EDITOR || process.env.VISUAL || 'vi';

  console.log(`Opening ${repoName} in ${editor}...`);

  // Open editor
  await new Promise((resolve, reject) => {
    const child = spawn(editor, [tempFile], {
      stdio: 'inherit'
    });

    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Editor exited with code ${code}`));
      }
    });

    child.on('error', reject);
  });

  // Read the edited content
  const newContent = fs.readFileSync(tempFile, 'utf8');

  // Clean up temp file
  fs.unlinkSync(tempFile);

  // Check if content changed
  if (newContent === content) {
    console.log('No changes made.');
    return;
  }

  console.log('Encrypting updated secrets...');

  // Generate new DEK
  const newDEK = crypto.generateDEK();

  // Encrypt the new content
  const newEncryptedSecrets = crypto.encrypt(Buffer.from(newContent, 'utf8'), newDEK);

  // Re-wrap DEK for all recipients
  const newRecipients = {};
  for (const [fp, recipientData] of Object.entries(recipients)) {
    const recipientPubKey = crypto.decodePublicKey(recipientData.publicKey);
    const newWrappedDEK = crypto.sealBox(newDEK, recipientPubKey);
    newRecipients[fp] = {
      publicKey: recipientData.publicKey,
      wrappedDEK: newWrappedDEK.toString('base64')
    };
  }

  // Save
  vault.saveSecrets(repoName, newEncryptedSecrets);
  vault.saveRecipients(repoName, newRecipients, dek_version + 1);

  console.log(`Updated "${repoName}"`);
  console.log(`DEK version: ${dek_version + 1}`);
}

module.exports = edit;
