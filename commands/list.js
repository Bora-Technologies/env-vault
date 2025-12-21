const vault = require('../lib/vault');

function list() {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  if (vault.hasLocalVault()) {
    try {
      const repoName = vault.getRepoNameFromDir();
      const localDir = vault.getLocalVaultDir();
      const { dek_version, recipients } = vault.loadLocalRecipients();
      const recipientCount = Object.keys(recipients).length;

      console.log('Local Vault (current directory):');
      console.log(`  Repo: ${repoName}`);
      console.log(`  Path: ${localDir}`);
      console.log(`  Recipients: ${recipientCount}`);
      console.log(`  DEK version: ${dek_version}`);
      console.log();
    } catch (e) {
      console.log('Local Vault (metadata unavailable)');
      console.log();
    }
  }

  // Global repos
  const repos = vault.listRepos();

  if (repos.length > 0) {
    console.log('Global Repositories:\n');
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
  } else if (!vault.hasLocalVault()) {
    console.log('No repositories found.');
    console.log('Add one with: env-vault add <repo> <file>');
    console.log('Or initialize local: env-vault init-repo');
  }
}

module.exports = list;
