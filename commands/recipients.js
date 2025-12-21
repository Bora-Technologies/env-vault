const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');

function recipients(repoName) {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  if (!vault.repoExists(repoName)) {
    console.error(`Repository "${repoName}" not found`);
    process.exit(1);
  }

  const publicKey = vault.loadPublicKey();
  const myFingerprint = crypto.getFingerprint(publicKey);
  const config = vault.loadConfig();

  const { dek_version, recipients: recipientsList } = vault.loadRecipients(repoName);

  console.log(`Recipients for "${repoName}":\n`);
  console.log(`DEK version: ${dek_version}\n`);

  const fingerprints = Object.keys(recipientsList);

  if (fingerprints.length === 0) {
    console.log('No recipients (this shouldn\'t happen)');
    return;
  }

  for (const fp of fingerprints) {
    const recipientData = recipientsList[fp];
    const isMe = fp === myFingerprint;

    // Get label - for self, use device label from config
    let label = recipientData.label || '';
    if (isMe && config.deviceLabel) {
      label = config.deviceLabel;
    }

    const youTag = isMe ? ' (you)' : '';
    const addedAt = recipientData.addedAt ? ` - added ${new Date(recipientData.addedAt).toLocaleDateString()}` : '';

    console.log(`  ${fp}${youTag}`);
    if (label) {
      console.log(`    Label: ${label}${addedAt}`);
    }
    console.log();
  }

  console.log(`Total: ${fingerprints.length} recipient(s)`);
}

module.exports = recipients;
