const fs = require('fs');
const crypto = require('@env-vault/crypto');
const vault = require('../lib/vault');
const { unlockVault } = require('../lib/unlock');
const inquirer = require('inquirer');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
    process.stdin.resume();
  });
}

async function promptForDetails(repoName, filePath) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return { proceed: true, meta: null };
  }

  const sourceLabel = filePath ? filePath : (fs.existsSync('.env') ? '.env (found in current dir)' : 'stdin');
  const { proceed } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'proceed',
      message: `Add secrets to repo "${repoName}" from ${sourceLabel}?`,
      default: true
    }
  ]);

  if (!proceed) {
    return { proceed: false, meta: null };
  }

  const { wantsMeta } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'wantsMeta',
      message: 'Add a tag/note for this repo?',
      default: false
    }
  ]);

  if (!wantsMeta) {
    return { proceed: true, meta: null };
  }

  const { tag, note } = await inquirer.prompt([
    {
      type: 'input',
      name: 'tag',
      message: 'Tag (optional):'
    },
    {
      type: 'input',
      name: 'note',
      message: 'Note (optional):'
    }
  ]);

  const trimmedTag = (tag || '').trim();
  const trimmedNote = (note || '').trim();
  if (!trimmedTag && !trimmedNote) {
    return { proceed: true, meta: null };
  }

  const meta = {};
  if (trimmedTag) meta.tag = trimmedTag;
  if (trimmedNote) meta.note = trimmedNote;
  return { proceed: true, meta };
}

async function add(repoName, filePath, options = {}) {
  if (filePath && !fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }

  // Determine if using local or central storage
  // If no repo provided, default to local if initialized or in generic context
  let targetRepo = repoName;
  if (!targetRepo) {
    if (vault.hasLocalVault()) {
      targetRepo = '.';
    } else {
      console.error('Missing repository argument.');
      console.error('Usage: env-vault add <repo> [file]');
      console.error('Or run "env-vault init-repo" to start a local vault first.');
      process.exit(1);
    }
  }

  const useLocal = options.local || targetRepo === '.' || (vault.hasLocalVault() && targetRepo === vault.getRepoNameFromDir());

  const displayName = useLocal ? vault.getRepoNameFromDir() : targetRepo;

  const { proceed, meta } = await promptForDetails(displayName, filePath);
  if (!proceed) {
    console.log('Aborted.');
    return;
  }

  // Read the content
  let content;
  if (filePath) {
    content = fs.readFileSync(filePath, 'utf8');
  } else {
    // Check if .env exists in current directory
    if (fs.existsSync('.env')) {
      // We already prompted user above confirmation to use found .env or stdin is implied if they said yes to sourceLabel check
      // But wait, promptForDetails sourceLabel logic was just display text. We need to actually align logic.
      // The prompt text said "from .env (found...)" so we should use it.
      content = fs.readFileSync('.env', 'utf8');
    } else {
      // Read from stdin
      console.log('Reading from stdin (Ctrl+D to finish)...');
      content = await readStdin();
    }
  }

  if (!content || content.trim() === '') {
    console.error('No content provided');
    process.exit(1);
  }

  // Unlock vault to get private key
  const privateKey = await unlockVault();
  const publicKey = vault.loadPublicKey();
  const fingerprint = crypto.getFingerprint(publicKey);

  // Check if repo already exists
  const isUpdate = useLocal ? vault.hasLocalVault() : vault.repoExists(targetRepo);

  // Generate a new DEK (Data Encryption Key)
  const dek = crypto.generateDEK();

  // Encrypt the content with DEK
  const encryptedContent = crypto.encrypt(Buffer.from(content, 'utf8'), dek);

  // Build recipients object
  let recipients = {};
  let dekVersion = 1;

  // If updating, re-wrap DEK for all existing recipients
  if (isUpdate) {
    try {
      const existing = useLocal
        ? vault.loadLocalRecipients()
        : vault.loadRecipients(targetRepo);
      dekVersion = (existing.dek_version || 0) + 1;

      // Re-wrap DEK for all existing recipients
      for (const [fp, recipientData] of Object.entries(existing.recipients)) {
        const recipientPubKey = crypto.decodePublicKey(recipientData.publicKey);
        const newWrappedDEK = crypto.sealBox(dek, recipientPubKey);
        recipients[fp] = {
          ...recipientData,
          wrappedDEK: newWrappedDEK.toString('base64')
        };
      }
    } catch (e) {
      // No existing recipients, start fresh
    }
  }

  // Wrap DEK for ourselves (overwrites if we're already a recipient)
  const wrappedDEK = crypto.sealBox(dek, publicKey);
  const config = vault.loadConfig();
  recipients[fingerprint] = {
    label: config.deviceLabel || 'Owner',
    publicKey: crypto.encodePublicKey(publicKey),
    wrappedDEK: wrappedDEK.toString('base64'),
    addedAt: recipients[fingerprint]?.addedAt || new Date().toISOString()
  };

  // Save to appropriate location
  if (useLocal) {
    vault.initLocalVault(); // Ensure directory exists
    vault.saveLocalSecrets(encryptedContent);
    vault.saveLocalRecipients(recipients, dekVersion);
    if (meta) {
      vault.saveLocalMeta(meta);
    }
  } else {
    vault.createRepoDir(targetRepo);
    vault.saveSecrets(targetRepo, encryptedContent);
    vault.saveRecipients(targetRepo, recipients, dekVersion);
    if (meta) {
      vault.saveMeta(targetRepo, meta);
    }
  }

  if (isUpdate) {
    console.log(`Updated secrets for "${displayName}"`);
    console.log(`Re-wrapped DEK for ${Object.keys(recipients).length} recipient(s)`);
  } else {
    console.log(`Added secrets for "${displayName}"`);
  }
  console.log(`DEK version: ${dekVersion}`);
  if (useLocal) {
    console.log('Saved to: .env-vault/');
  }
}

module.exports = add;
