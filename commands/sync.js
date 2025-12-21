const simpleGit = require('simple-git');
const vault = require('../lib/vault');
const path = require('path');
const fs = require('fs');

async function sync() {
  if (!vault.isInitialized()) {
    console.error('Vault not initialized. Run: env-vault init');
    process.exit(1);
  }

  const git = simpleGit(vault.VAULT_DIR);

  // Check if git is initialized
  const isRepo = await git.checkIsRepo();

  if (!isRepo) {
    console.log('Initializing git repository in vault...');
    await git.init();

    // Create .gitignore to exclude identity (private key stays local)
    const gitignore = `# Never sync private key
identity/private.key
identity/salt
`;
    fs.writeFileSync(path.join(vault.VAULT_DIR, '.gitignore'), gitignore);

    console.log('Git repository initialized.');
    console.log('Set a remote with: git -C ~/.env-vault remote add origin <url>');
    return;
  }

  // Check for remote
  const remotes = await git.getRemotes();
  if (remotes.length === 0) {
    console.error('No git remote configured.');
    console.log('Add one with: git -C ~/.env-vault remote add origin <url>');
    process.exit(1);
  }

  console.log('Syncing vault...');

  // Pull first
  try {
    console.log('Pulling changes...');
    await git.pull('origin', 'main', { '--rebase': 'true' });
  } catch (err) {
    // Might fail if no upstream or first push
    if (!err.message.includes('no tracking information') &&
        !err.message.includes("couldn't find remote ref")) {
      console.warn('Pull warning:', err.message);
    }
  }

  // Add all changes
  await git.add('.');

  // Check if there are changes to commit
  const status = await git.status();
  if (status.staged.length > 0 || status.modified.length > 0 || status.created.length > 0) {
    console.log('Committing changes...');
    const timestamp = new Date().toISOString();
    await git.commit(`Sync: ${timestamp}`);
  } else {
    console.log('No local changes to commit.');
  }

  // Push
  try {
    console.log('Pushing changes...');
    await git.push('origin', 'main', { '-u': null });
    console.log('Sync complete!');
  } catch (err) {
    if (err.message.includes('failed to push')) {
      console.error('Push failed. You may need to pull and resolve conflicts first.');
    } else {
      throw err;
    }
  }
}

module.exports = sync;
