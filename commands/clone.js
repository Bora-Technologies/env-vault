const simpleGit = require('simple-git');
const vault = require('../lib/vault');
const fs = require('fs');
const path = require('path');
const inquirer = require('inquirer');
const crypto = require('@env-vault/crypto');

async function clone(gitUrl) {
  // Check if vault already exists
  if (vault.isInitialized()) {
    const { overwrite } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'overwrite',
        message: 'A vault already exists. This will overwrite the repos. Continue?',
        default: false
      }
    ]);

    if (!overwrite) {
      console.log('Aborted.');
      return;
    }
  }

  console.log(`Cloning vault from ${gitUrl}...`);

  // Create a temp directory for cloning
  const tempDir = path.join(vault.VAULT_DIR, '.clone-temp');

  try {
    // Clone to temp directory
    const git = simpleGit();
    await git.clone(gitUrl, tempDir);

    // Copy repos from cloned vault
    const clonedReposDir = path.join(tempDir, 'repos');
    if (fs.existsSync(clonedReposDir)) {
      // Create vault dirs if needed
      vault.initDirs();

      // Copy repos
      const repos = fs.readdirSync(clonedReposDir);
      for (const repo of repos) {
        const srcDir = path.join(clonedReposDir, repo);
        const destDir = vault.getRepoDir(repo);

        if (fs.statSync(srcDir).isDirectory()) {
          fs.cpSync(srcDir, destDir, { recursive: true });
          console.log(`  Imported: ${repo}`);
        }
      }
    }

    // Copy public keys directory if it exists
    const clonedPubKeysDir = path.join(tempDir, 'identity', 'public.key');
    // We don't copy this - each user should have their own identity

    // Copy config if it exists (but not identity)
    const clonedConfig = path.join(tempDir, 'config.json');
    if (fs.existsSync(clonedConfig)) {
      const config = JSON.parse(fs.readFileSync(clonedConfig, 'utf8'));
      config.clonedFrom = gitUrl;
      config.clonedAt = new Date().toISOString();
      vault.saveConfig(config);
    }

    // Initialize git in vault directory
    const vaultGit = simpleGit(vault.VAULT_DIR);
    if (!await vaultGit.checkIsRepo()) {
      await vaultGit.init();
    }

    // Set the remote
    const remotes = await vaultGit.getRemotes();
    if (!remotes.find(r => r.name === 'origin')) {
      await vaultGit.addRemote('origin', gitUrl);
    }

    // Create .gitignore
    const gitignore = `# Never sync private key
identity/private.key
identity/salt
`;
    fs.writeFileSync(path.join(vault.VAULT_DIR, '.gitignore'), gitignore);

    console.log('\nClone complete!');

    // Check if user has identity
    if (!vault.isInitialized()) {
      console.log('\nYou need to initialize your identity to access the secrets:');
      console.log('  env-vault init');
      console.log('\nThen ask the vault owner to share repos with your public key.');
    } else {
      console.log('\nYour identity is already set up.');
      console.log('Use "env-vault list" to see available repos.');
    }

  } finally {
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  }
}

module.exports = clone;
