/**
 * Initialize .env-vault in the current project directory
 *
 * This creates a per-repo encrypted storage that can be committed to git.
 * Team members with access can decrypt the secrets using their own identity.
 */
const fs = require('fs');
const path = require('path');
const inquirer = require('inquirer');
const vault = require('../lib/vault');
const crypto = require('@env-vault/crypto');
const { unlockVault } = require('../lib/unlock');

async function initRepo(envFile) {
  console.log('\n🔐 Initialize env-vault in project\n');

  // Check if already initialized
  if (vault.hasLocalVault()) {
    console.log('This directory already has an .env-vault folder.');

    const { overwrite } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'overwrite',
        message: 'Overwrite existing encrypted secrets?',
        default: false,
      },
    ]);

    if (!overwrite) {
      console.log('Aborted.');
      return;
    }
  }

  // Check if identity is initialized
  if (!vault.isInitialized()) {
    console.log('Vault identity not initialized.');
    console.log('Run: env-vault init');
    process.exit(1);
  }

  // Find .env file
  let envContent = null;
  let envFilePath = envFile;

  if (envFile) {
    if (!fs.existsSync(envFile)) {
      console.error(`File not found: ${envFile}`);
      process.exit(1);
    }
    envContent = fs.readFileSync(envFile, 'utf8');
  } else {
    // Look for common .env files
    const candidates = ['.env', '.env.local', '.env.development'];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        envFilePath = candidate;
        break;
      }
    }

    if (envFilePath) {
      const { useFound } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'useFound',
          message: `Found ${envFilePath}. Encrypt this file?`,
          default: true,
        },
      ]);

      if (useFound) {
        envContent = fs.readFileSync(envFilePath, 'utf8');
      }
    }

    if (!envContent) {
      console.log('No .env file specified or found.');
      console.log('Usage: env-vault init-repo [.env file]');
      console.log('');
      console.log('You can also create the vault now and add secrets later:');

      const { createEmpty } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'createEmpty',
          message: 'Create empty encrypted vault?',
          default: true,
        },
      ]);

      if (!createEmpty) {
        console.log('Aborted.');
        return;
      }

      envContent = '# Add your environment variables here\n';
    }
  }

  // Unlock vault to get identity
  console.log('\nUnlock your vault to encrypt the secrets...');
  const privateKey = await unlockVault();
  const publicKey = vault.loadPublicKey();
  const fingerprint = crypto.getFingerprint(publicKey);
  const config = vault.loadConfig();

  // Initialize local vault directory
  vault.initLocalVault();

  // Generate DEK and encrypt
  const dek = crypto.generateDEK();
  const encryptedContent = crypto.encrypt(Buffer.from(envContent, 'utf8'), dek);

  // Wrap DEK for owner
  const wrappedDEK = crypto.sealBox(dek, publicKey);

  const recipients = {
    [fingerprint]: {
      label: config.deviceLabel || 'Owner',
      publicKey: crypto.encodePublicKey(publicKey),
      wrappedDEK: wrappedDEK.toString('base64'),
      addedAt: new Date().toISOString(),
    },
  };

  // Save everything
  vault.saveLocalSecrets(encryptedContent);
  vault.saveLocalRecipients(recipients, 1);

  const repoName = vault.getRepoNameFromDir();
  const localDir = vault.getLocalVaultDir();

  console.log('\n✅ Encrypted vault created!');
  console.log('');
  console.log(`   Directory: ${localDir}`);
  console.log(`   Repo name: ${repoName}`);
  console.log(`   Your fingerprint: ${fingerprint}`);
  console.log('');
  console.log('📝 Next steps:');
  console.log('   1. Commit .env-vault/ to your repository');
  console.log('   2. Share access: env-vault share <email>');
  console.log('   3. Get secrets: env-vault get .');
  console.log('');

  // Suggest adding to .gitignore
  const gitignorePath = path.join(process.cwd(), '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, 'utf8');
    if (!gitignore.includes('.env')) {
      console.log('⚠️  Consider adding .env files to your .gitignore:');
      console.log('   echo ".env*" >> .gitignore');
      console.log('');
    }
  }
}

module.exports = initRepo;
