/**
 * Push local secrets to Supabase backend
 *
 * This syncs the local .env-vault/ with the backend so:
 * - Mobile apps can access the encrypted secrets
 * - Wrapped DEKs are stored for all recipients
 */
const vault = require('../lib/vault');
const supabase = require('../lib/supabase');
const crypto = require('@env-vault/crypto');
const { unlockVault } = require('../lib/unlock');
const fs = require('fs');

async function push() {
  console.log('\n📤 Push to Backend\n');

  // Check if linked to account
  if (!supabase.isLinked()) {
    console.error('Not linked to an account.');
    console.error('Run: env-vault device link');
    process.exit(1);
  }

  // Check if local vault exists
  if (!vault.hasLocalVault()) {
    console.error('No .env-vault found in this directory.');
    console.error('Run: env-vault init-repo');
    process.exit(1);
  }

  const account = supabase.getLinkedAccount();
  const repoName = vault.getRepoNameFromDir();

  console.log(`Repo: ${repoName}`);
  console.log(`Account: ${account.email}`);
  console.log('');

  try {
    // Load local data
    const encryptedSecrets = vault.loadLocalSecrets();
    const { dek_version, recipients } = vault.loadLocalRecipients();

    // Unlock to verify we have access
    const privateKey = await unlockVault();
    const publicKey = vault.loadPublicKey();
    const fingerprint = crypto.getFingerprint(publicKey);

    if (!recipients[fingerprint]) {
      console.error('You do not have access to this repository.');
      process.exit(1);
    }

    console.log('Creating/updating repo on backend...');

    // Create or update repo on backend
    const repo = await supabase.upsertRepo(repoName);
    console.log(`Repo ID: ${repo.id}`);

    // Upload encrypted secrets cache (for mobile)
    console.log('Uploading encrypted secrets...');
    await supabase.uploadSecretsCache(
      repo.id,
      encryptedSecrets.toString('base64'),
      dek_version
    );

    // Get device IDs for all recipients and upload wrapped DEKs
    console.log('Syncing wrapped DEKs...');

    // For each recipient, look up their device ID on the backend
    // For now, we'll upload DEKs keyed by fingerprint and let the backend resolve
    const wrappedDeks = [];
    for (const [fp, recipientData] of Object.entries(recipients)) {
      // Try to find this device on backend
      try {
        const client = supabase.getClient();
        const { data: device } = await client
          .from('devices')
          .select('id')
          .eq('fingerprint', fp)
          .single();

        if (device) {
          wrappedDeks.push({
            deviceId: device.id,
            wrappedDek: recipientData.wrappedDEK,
          });
        }
      } catch (e) {
        // Device not registered on backend, skip
        console.log(`  Skipping unregistered device: ${fp.slice(0, 8)}...`);
      }
    }

    if (wrappedDeks.length > 0) {
      await supabase.uploadWrappedDeks(repo.id, wrappedDeks, dek_version);
      console.log(`Uploaded ${wrappedDeks.length} wrapped DEK(s)`);
    }

    console.log('\n✅ Push complete!');
    console.log('');
    console.log('Mobile devices linked to your account can now access this repo.');
    console.log('');
  } catch (error) {
    console.error('\n❌ Push failed:', error.message);
    process.exit(1);
  }
}

module.exports = push;
