const fs = require('fs');
const inquirer = require('inquirer');
const vault = require('../lib/vault');

async function reset(options = {}) {
  console.log('\n⚠️  Reset env-vault\n');

  if (!vault.isInitialized()) {
    console.log('No vault found. Nothing to reset.');
    return;
  }

  console.log('This will permanently delete:');
  console.log(`  • Your identity (keypair) at ~/.env-vault/identity/`);
  console.log(`  • All stored repositories at ~/.env-vault/repos/`);
  console.log(`  • Your vault configuration`);
  console.log('');
  console.log('⚠️  WARNING: You will lose access to ALL encrypted secrets!');
  console.log('   Make sure you have backups or can re-share from teammates.');
  console.log('');

  if (!options.force) {
    const { confirm } = await inquirer.prompt([
      {
        type: 'input',
        name: 'confirm',
        message: 'Type "DELETE" to confirm:',
      }
    ]);

    if (confirm !== 'DELETE') {
      console.log('Aborted. Nothing was deleted.');
      return;
    }
  }

  try {
    // Delete the entire vault directory
    if (fs.existsSync(vault.VAULT_DIR)) {
      fs.rmSync(vault.VAULT_DIR, { recursive: true });
    }

    console.log('\n✅ Vault deleted successfully.');
    console.log('');
    console.log('To start fresh, run:');
    console.log('  env-vault init');
    console.log('');
  } catch (err) {
    console.error('Failed to delete vault:', err.message);
    process.exit(1);
  }
}

module.exports = reset;
