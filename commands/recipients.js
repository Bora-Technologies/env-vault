const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');

function recipients(repoName) {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  // Handle optional repoName
  let targetRepo = repoName;
  let isLocal = targetRepo === '.' || !targetRepo;

  // If not explicitly '.', check if it matches the local repo name
  if (!isLocal && vault.hasLocalVault()) {
    const localRepoName = vault.getRepoNameFromDir();
    if (targetRepo === localRepoName) {
      isLocal = true;
    }
  }

  if (isLocal) {
    if (!vault.hasLocalVault()) {
      if (!targetRepo) {
        console.error('No repository specified and no .env-vault found in this directory.');
        console.error('Usage: env-vault recipients <repo>');
        process.exit(1);
      } else {
        console.error('No .env-vault found in this directory.');
        console.error('Run: env-vault init-repo');
        process.exit(1);
      }
    }
    // If we defaulted to local, let the user know
    if (!targetRepo) {
      const localRepoName = vault.getRepoNameFromDir();
      console.log(`Showing recipients for local repository "${localRepoName}"`);
      console.log(`(To view another repository, use: env-vault recipients <repo_name>)\n`);
    }
  } else {
    // If checking a specific named repo that isn't local
    if (!vault.repoExists(targetRepo)) {
      console.error(`Repository "${targetRepo}" not found`);
      process.exit(1);
    }
  }

  const publicKey = vault.loadPublicKey();
  const myFingerprint = crypto.getFingerprint(publicKey);
  const config = vault.loadConfig();

  const { dek_version, recipients: recipientsList } = isLocal
    ? vault.loadLocalRecipients()
    : vault.loadRecipients(targetRepo);

  const displayName = isLocal ? vault.getRepoNameFromDir() : targetRepo;

  console.log(`Recipients for "${displayName}":\n`);
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
