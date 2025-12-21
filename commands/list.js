const vault = require('../lib/vault');

function list() {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  const repos = vault.listRepos();

  if (repos.length === 0) {
    console.log('No repositories found.');
    console.log('Add one with: env-vault add <repo> <file>');
    return;
  }

  console.log('Repositories:\n');
  for (const repo of repos) {
    try {
      const { dek_version, recipients } = vault.loadRecipients(repo);
      const recipientCount = Object.keys(recipients).length;
      console.log(`  ${repo}`);
      console.log(`    Recipients: ${recipientCount}`);
      console.log(`    DEK version: ${dek_version}`);
      console.log();
    } catch (e) {
      console.log(`  ${repo} (metadata unavailable)`);
    }
  }
}

module.exports = list;
