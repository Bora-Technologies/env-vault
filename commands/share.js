const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const { unlockVault } = require('../lib/unlock');
const inquirer = require('inquirer');

async function share(repoName, pubkeyBase64, label) {
  if (!vault.repoExists(repoName)) {
    console.error(`Repository "${repoName}" not found`);
    process.exit(1);
  }

  // Decode the recipient's public key
  let recipientPubKey;
  try {
    recipientPubKey = crypto.decodePublicKey(pubkeyBase64);
  } catch (err) {
    console.error('Invalid public key format. It should be base64 encoded.');
    process.exit(1);
  }

  const recipientFingerprint = crypto.getFingerprint(recipientPubKey);

  // Prompt for label if not provided
  let recipientLabel = label;
  if (!recipientLabel) {
    const { inputLabel } = await inquirer.prompt([
      {
        type: 'input',
        name: 'inputLabel',
        message: 'Label for this recipient (e.g., "John\'s laptop", "My iPhone"):',
        default: `Device ${recipientFingerprint.slice(0, 8)}`
      }
    ]);
    recipientLabel = inputLabel;
  }

  // Unlock vault to get our private key
  const privateKey = await unlockVault();
  const publicKey = vault.loadPublicKey();
  const myFingerprint = crypto.getFingerprint(publicKey);

  // Load recipients
  const { dek_version, recipients } = vault.loadRecipients(repoName);

  // Check if recipient already has access
  if (recipients[recipientFingerprint]) {
    console.log(`Recipient ${recipientFingerprint} already has access to "${repoName}"`);
    console.log(`Label: ${recipients[recipientFingerprint].label || '(none)'}`);
    return;
  }

  // Find our wrapped DEK
  const myRecipientData = recipients[myFingerprint];
  if (!myRecipientData) {
    console.error(`You don't have access to "${repoName}"`);
    process.exit(1);
  }

  // Unwrap the DEK using our private key
  const wrappedDEK = Buffer.from(myRecipientData.wrappedDEK, 'base64');
  let dek;
  try {
    dek = crypto.openBox(wrappedDEK, privateKey);
  } catch (err) {
    console.error('Failed to decrypt DEK. The data may be corrupted.');
    process.exit(1);
  }

  // Wrap the DEK for the new recipient
  const newWrappedDEK = crypto.sealBox(dek, recipientPubKey);

  // Add the new recipient with label
  recipients[recipientFingerprint] = {
    label: recipientLabel,
    publicKey: pubkeyBase64,
    wrappedDEK: newWrappedDEK.toString('base64'),
    addedAt: new Date().toISOString()
  };

  // Save updated recipients
  vault.saveRecipients(repoName, recipients, dek_version);

  console.log(`\nShared "${repoName}" with:`);
  console.log(`  Label: ${recipientLabel}`);
  console.log(`  Fingerprint: ${recipientFingerprint}`);
  console.log(`\nTotal recipients: ${Object.keys(recipients).length}`);
}

module.exports = share;
