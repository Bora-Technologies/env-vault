const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const { unlockVault } = require('../lib/unlock');
const inquirer = require('inquirer');

async function revoke(repoName, fingerprint) {
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

  // Check if trying to revoke ourselves
  if (fingerprint === myFingerprint) {
    console.error('Cannot revoke your own access.');
    process.exit(1);
  }

  // Check if recipient exists
  if (!recipients[fingerprint]) {
    console.error(`Recipient "${fingerprint}" not found in "${repoName}"`);
    console.log('\nCurrent recipients:');
    for (const fp of Object.keys(recipients)) {
      console.log(`  ${fp}${fp === myFingerprint ? ' (you)' : ''}`);
    }
    process.exit(1);
  }

  // Find our wrapped DEK
  const myRecipientData = recipients[myFingerprint];
  if (!myRecipientData) {
    console.error(`You don't have access to "${repoName}"`);
    process.exit(1);
  }

  // Confirm revocation
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: `Revoke access for ${fingerprint}? This will re-encrypt the secrets with a new key.`,
      default: true
    }
  ]);

  if (!confirm) {
    console.log('Aborted.');
    return;
  }

  console.log('Revoking access...');

  // Unwrap the current DEK
  const wrappedDEK = Buffer.from(myRecipientData.wrappedDEK, 'base64');
  let oldDEK;
  try {
    oldDEK = crypto.openBox(wrappedDEK, privateKey);
  } catch (err) {
    console.error('Failed to decrypt DEK. The data may be corrupted.');
    process.exit(1);
  }

  // Decrypt the current secrets
  const encryptedSecrets = vault.loadSecrets(repoName);
  let decryptedSecrets;
  try {
    decryptedSecrets = crypto.decrypt(encryptedSecrets, oldDEK);
  } catch (err) {
    console.error('Failed to decrypt secrets. The data may be corrupted.');
    process.exit(1);
  }

  // Generate a new DEK
  const newDEK = crypto.generateDEK();

  // Re-encrypt the secrets with the new DEK
  const newEncryptedSecrets = crypto.encrypt(decryptedSecrets, newDEK);

  // Build new recipients (excluding the revoked one)
  const newRecipients = {};
  for (const [fp, recipientData] of Object.entries(recipients)) {
    if (fp === fingerprint) {
      continue; // Skip the revoked recipient
    }

    // Re-wrap the new DEK for this recipient
    const recipientPubKey = crypto.decodePublicKey(recipientData.publicKey);
    const newWrappedDEK = crypto.sealBox(newDEK, recipientPubKey);
    newRecipients[fp] = {
      publicKey: recipientData.publicKey,
      wrappedDEK: newWrappedDEK.toString('base64')
    };
  }

  // Save the new secrets and recipients
  vault.saveSecrets(repoName, newEncryptedSecrets);
  vault.saveRecipients(repoName, newRecipients, dek_version + 1);

  console.log(`\nRevoked access for ${fingerprint}`);
  console.log(`Re-wrapped DEK for ${Object.keys(newRecipients).length} remaining recipient(s)`);
  console.log(`New DEK version: ${dek_version + 1}`);
  console.log('\nDon\'t forget to sync to propagate changes: env-vault sync');
}

module.exports = revoke;
