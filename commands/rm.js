const vault = require('../lib/vault');
const inquirer = require('inquirer');

async function rm(repoName, options) {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  if (!vault.repoExists(repoName)) {
    console.error(`Repository "${repoName}" not found`);
    process.exit(1);
  }

  // Confirm unless --force
  if (!options.force) {
    const { confirm } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'confirm',
        message: `Are you sure you want to delete "${repoName}"? This cannot be undone.`,
        default: false
      }
    ]);

    if (!confirm) {
      console.log('Aborted.');
      return;
    }
  }

  vault.deleteRepo(repoName);
  console.log(`Deleted "${repoName}"`);
}

module.exports = rm;
