const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// Secure file permissions
const FILE_MODE = 0o600;  // Owner read/write only
const DIR_MODE = 0o700;   // Owner read/write/execute only

// Central vault directory (for identity only)
const VAULT_DIR = path.join(os.homedir(), '.env-vault');

/**
 * Write file atomically with secure permissions
 * Uses write-to-temp + rename pattern to prevent corruption
 * @param {string} filePath - Target file path
 * @param {Buffer|string} data - Data to write
 * @param {object} options - Options including mode
 */
function secureWriteFileSync(filePath, data, options = {}) {
  const mode = options.mode || FILE_MODE;
  const dir = path.dirname(filePath);
  const tempFile = path.join(dir, `.tmp-${crypto.randomBytes(8).toString('hex')}`);

  try {
    // Write to temp file with restrictive permissions
    fs.writeFileSync(tempFile, data, { mode });

    // Sync to disk
    const fd = fs.openSync(tempFile, 'r');
    fs.fsyncSync(fd);
    fs.closeSync(fd);

    // Atomic rename
    fs.renameSync(tempFile, filePath);

    // Ensure final permissions (rename may preserve old perms on some systems)
    fs.chmodSync(filePath, mode);
  } catch (err) {
    // Clean up temp file on error
    try {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    } catch (cleanupErr) {
      // Ignore cleanup errors
    }
    throw err;
  }
}

/**
 * Create directory with secure permissions
 * @param {string} dirPath - Directory path
 */
function secureCreateDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode: DIR_MODE });
  }
  // Ensure permissions even if directory existed
  fs.chmodSync(dirPath, DIR_MODE);
}

/**
 * Check if file has secure permissions (owner-only)
 * @param {string} filePath - File path to check
 * @returns {{secure: boolean, mode: string, issues: string[]}}
 */
function checkFilePermissions(filePath) {
  const issues = [];

  if (!fs.existsSync(filePath)) {
    return { secure: true, mode: null, issues: [] };
  }

  const stats = fs.statSync(filePath);
  const mode = stats.mode & 0o777;

  if (mode & 0o077) {  // Group or world permissions
    issues.push(`File ${filePath} has insecure permissions: ${mode.toString(8)}`);
  }

  return {
    secure: issues.length === 0,
    mode: mode.toString(8),
    issues
  };
}

/**
 * Validate repository name to prevent path traversal and invalid characters
 * @param {string} name - Repository name to validate
 * @returns {string} - Validated name
 * @throws {Error} - If name is invalid
 */
function validateRepoName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Repository name is required');
  }

  const trimmed = name.trim();

  if (trimmed.length === 0) {
    throw new Error('Repository name cannot be empty');
  }

  if (trimmed.length > 100) {
    throw new Error('Repository name too long (max 100 characters)');
  }

  // Only allow alphanumeric, hyphens, underscores, and dots (but not starting with dot)
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(trimmed)) {
    throw new Error('Repository name can only contain letters, numbers, hyphens, underscores, and dots (cannot start with a dot)');
  }

  // Prevent path traversal
  if (trimmed.includes('..') || trimmed.includes('/') || trimmed.includes('\\')) {
    throw new Error('Repository name contains invalid characters');
  }

  return trimmed;
}
const IDENTITY_DIR = path.join(VAULT_DIR, 'identity');
const REPOS_DIR = path.join(VAULT_DIR, 'repos');
const CONFIG_FILE = path.join(VAULT_DIR, 'config.json');
const PRIVATE_KEY_FILE = path.join(IDENTITY_DIR, 'private.key');
const PUBLIC_KEY_FILE = path.join(IDENTITY_DIR, 'public.key');
const SALT_FILE = path.join(IDENTITY_DIR, 'salt');
const META_FILE_NAME = 'meta.json';

// Per-repo storage (in project directory)
const LOCAL_VAULT_DIR = '.env-vault';
const LOCAL_SECRETS_FILE = 'secrets.enc';
const LOCAL_RECIPIENTS_FILE = 'recipients.json';
const LOCAL_META_FILE = 'meta.json';

/**
 * Check if vault is initialized
 * @returns {boolean}
 */
function isInitialized() {
  return fs.existsSync(PRIVATE_KEY_FILE) && fs.existsSync(PUBLIC_KEY_FILE);
}

/**
 * Initialize vault directory structure with secure permissions
 */
function initDirs() {
  secureCreateDir(VAULT_DIR);
  secureCreateDir(IDENTITY_DIR);
  secureCreateDir(REPOS_DIR);
}

/**
 * Save encrypted private key with secure permissions (0600)
 * @param {Buffer} encryptedKey - Encrypted private key (salt + iv + ciphertext + tag)
 * @param {Buffer} salt - KDF salt
 */
function savePrivateKey(encryptedKey, salt) {
  secureWriteFileSync(PRIVATE_KEY_FILE, encryptedKey);
  secureWriteFileSync(SALT_FILE, salt);
}

/**
 * Load encrypted private key
 * @returns {{encryptedKey: Buffer, salt: Buffer}}
 */
function loadPrivateKey() {
  if (!fs.existsSync(PRIVATE_KEY_FILE) || !fs.existsSync(SALT_FILE)) {
    throw new Error('Vault not initialized. Run: env-vault init');
  }
  return {
    encryptedKey: fs.readFileSync(PRIVATE_KEY_FILE),
    salt: fs.readFileSync(SALT_FILE)
  };
}

/**
 * Save public key with secure permissions
 * @param {Buffer} publicKey - X25519 public key
 */
function savePublicKey(publicKey) {
  secureWriteFileSync(PUBLIC_KEY_FILE, publicKey);
}

/**
 * Load public key
 * @returns {Buffer}
 */
function loadPublicKey() {
  if (!fs.existsSync(PUBLIC_KEY_FILE)) {
    throw new Error('Vault not initialized. Run: env-vault init');
  }
  return fs.readFileSync(PUBLIC_KEY_FILE);
}

/**
 * Save config with secure permissions
 * @param {object} config
 */
function saveConfig(config) {
  secureWriteFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

/**
 * Load config
 * @returns {object}
 */
function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
}

/**
 * Get repo directory path
 * @param {string} repoName
 * @returns {string}
 */
function getRepoDir(repoName) {
  const validName = validateRepoName(repoName);
  return path.join(REPOS_DIR, validName);
}

/**
 * Get secrets file path for a repo
 * @param {string} repoName
 * @returns {string}
 */
function getSecretsFile(repoName) {
  return path.join(getRepoDir(repoName), 'secrets.enc');
}

/**
 * Get recipients file path for a repo
 * @param {string} repoName
 * @returns {string}
 */
function getRecipientsFile(repoName) {
  return path.join(getRepoDir(repoName), 'recipients.json');
}

/**
 * Get metadata file path for a repo
 * @param {string} repoName
 * @returns {string}
 */
function getMetaFile(repoName) {
  return path.join(getRepoDir(repoName), META_FILE_NAME);
}

/**
 * List all repos
 * @returns {string[]}
 */
function listRepos() {
  if (!fs.existsSync(REPOS_DIR)) {
    return [];
  }
  return fs.readdirSync(REPOS_DIR).filter(name => {
    const repoDir = path.join(REPOS_DIR, name);
    return fs.statSync(repoDir).isDirectory() && fs.existsSync(path.join(repoDir, 'secrets.enc'));
  });
}

/**
 * Check if repo exists
 * @param {string} repoName
 * @returns {boolean}
 */
function repoExists(repoName) {
  return fs.existsSync(getSecretsFile(repoName));
}

/**
 * Create repo directory with secure permissions
 * @param {string} repoName
 */
function createRepoDir(repoName) {
  secureCreateDir(getRepoDir(repoName));
}

/**
 * Delete repo
 * @param {string} repoName
 */
function deleteRepo(repoName) {
  const repoDir = getRepoDir(repoName);
  if (fs.existsSync(repoDir)) {
    fs.rmSync(repoDir, { recursive: true });
  }
}

/**
 * Save recipients for a repo with secure permissions
 * @param {string} repoName
 * @param {object} recipients - { fingerprint: { publicKey: base64, wrappedDEK: base64 }, ... }
 * @param {number} dekVersion
 */
function saveRecipients(repoName, recipients, dekVersion) {
  const data = {
    dek_version: dekVersion,
    recipients
  };
  secureWriteFileSync(getRecipientsFile(repoName), JSON.stringify(data, null, 2));
}

/**
 * Load recipients for a repo
 * @param {string} repoName
 * @returns {{dek_version: number, recipients: object}}
 */
function loadRecipients(repoName) {
  const file = getRecipientsFile(repoName);
  if (!fs.existsSync(file)) {
    throw new Error(`Repo "${repoName}" not found`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Save metadata for a repo with secure permissions
 * @param {string} repoName
 * @param {object} meta
 */
function saveMeta(repoName, meta) {
  secureWriteFileSync(getMetaFile(repoName), JSON.stringify(meta, null, 2));
}

/**
 * Load metadata for a repo
 * @param {string} repoName
 * @returns {object|null}
 */
function loadMeta(repoName) {
  const file = getMetaFile(repoName);
  if (!fs.existsSync(file)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Save encrypted secrets for a repo with secure permissions
 * @param {string} repoName
 * @param {Buffer} encryptedSecrets
 */
function saveSecrets(repoName, encryptedSecrets) {
  secureWriteFileSync(getSecretsFile(repoName), encryptedSecrets);
}

/**
 * Load encrypted secrets for a repo
 * @param {string} repoName
 * @returns {Buffer}
 */
function loadSecrets(repoName) {
  const file = getSecretsFile(repoName);
  if (!fs.existsSync(file)) {
    throw new Error(`Repo "${repoName}" not found`);
  }
  return fs.readFileSync(file);
}

// ============================================
// Per-Repo Storage Functions
// Store encrypted secrets in project directory
// ============================================

/**
 * Get local vault directory path for current working directory
 * @param {string} [projectDir] - Project directory, defaults to cwd
 * @returns {string}
 */
function getLocalVaultDir(projectDir = process.cwd()) {
  return path.join(projectDir, LOCAL_VAULT_DIR);
}

/**
 * Check if local vault exists in a directory
 * @param {string} [projectDir]
 * @returns {boolean}
 */
function hasLocalVault(projectDir = process.cwd()) {
  const localDir = getLocalVaultDir(projectDir);
  return fs.existsSync(path.join(localDir, LOCAL_SECRETS_FILE));
}

/**
 * Initialize local vault in a project directory with secure permissions
 * @param {string} [projectDir]
 */
function initLocalVault(projectDir = process.cwd()) {
  const localDir = getLocalVaultDir(projectDir);
  secureCreateDir(localDir);

  // Create .gitignore to prevent committing plaintext
  // .gitignore can have normal permissions since it's not sensitive
  const gitignorePath = path.join(localDir, '.gitignore');
  const gitignoreContent = `# Never commit plaintext secrets
*.env
*.env.*
!*.enc
`;
  fs.writeFileSync(gitignorePath, gitignoreContent, { mode: 0o644 });
}

/**
 * Get local secrets file path
 * @param {string} [projectDir]
 * @returns {string}
 */
function getLocalSecretsFile(projectDir = process.cwd()) {
  return path.join(getLocalVaultDir(projectDir), LOCAL_SECRETS_FILE);
}

/**
 * Get local recipients file path
 * @param {string} [projectDir]
 * @returns {string}
 */
function getLocalRecipientsFile(projectDir = process.cwd()) {
  return path.join(getLocalVaultDir(projectDir), LOCAL_RECIPIENTS_FILE);
}

/**
 * Get local meta file path
 * @param {string} [projectDir]
 * @returns {string}
 */
function getLocalMetaFile(projectDir = process.cwd()) {
  return path.join(getLocalVaultDir(projectDir), LOCAL_META_FILE);
}

/**
 * Save encrypted secrets to local vault with secure permissions
 * @param {Buffer} encryptedSecrets
 * @param {string} [projectDir]
 */
function saveLocalSecrets(encryptedSecrets, projectDir = process.cwd()) {
  secureWriteFileSync(getLocalSecretsFile(projectDir), encryptedSecrets);
}

/**
 * Load encrypted secrets from local vault
 * @param {string} [projectDir]
 * @returns {Buffer}
 */
function loadLocalSecrets(projectDir = process.cwd()) {
  const file = getLocalSecretsFile(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error('No encrypted secrets found in this directory. Run: env-vault init-repo');
  }
  return fs.readFileSync(file);
}

/**
 * Save recipients to local vault with secure permissions
 * @param {object} recipients
 * @param {number} dekVersion
 * @param {string} [projectDir]
 */
function saveLocalRecipients(recipients, dekVersion, projectDir = process.cwd()) {
  const data = {
    dek_version: dekVersion,
    recipients
  };
  secureWriteFileSync(getLocalRecipientsFile(projectDir), JSON.stringify(data, null, 2));
}

/**
 * Load recipients from local vault
 * @param {string} [projectDir]
 * @returns {{dek_version: number, recipients: object}}
 */
function loadLocalRecipients(projectDir = process.cwd()) {
  const file = getLocalRecipientsFile(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error('No recipients file found. Run: env-vault init-repo');
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Save metadata to local vault with secure permissions
 * @param {object} meta
 * @param {string} [projectDir]
 */
function saveLocalMeta(meta, projectDir = process.cwd()) {
  secureWriteFileSync(getLocalMetaFile(projectDir), JSON.stringify(meta, null, 2));
}

/**
 * Load metadata from local vault
 * @param {string} [projectDir]
 * @returns {object|null}
 */
function loadLocalMeta(projectDir = process.cwd()) {
  const file = getLocalMetaFile(projectDir);
  if (!fs.existsSync(file)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Delete local vault
 * @param {string} [projectDir]
 */
function deleteLocalVault(projectDir = process.cwd()) {
  const localDir = getLocalVaultDir(projectDir);
  if (fs.existsSync(localDir)) {
    fs.rmSync(localDir, { recursive: true });
  }
}

/**
 * Get repo name from project directory
 * @param {string} [projectDir]
 * @returns {string}
 */
function getRepoNameFromDir(projectDir = process.cwd()) {
  return path.basename(projectDir);
}

module.exports = {
  // Constants
  VAULT_DIR,
  IDENTITY_DIR,
  REPOS_DIR,
  LOCAL_VAULT_DIR,
  FILE_MODE,
  DIR_MODE,
  // Security utilities
  secureWriteFileSync,
  secureCreateDir,
  checkFilePermissions,
  // Core functions
  validateRepoName,
  isInitialized,
  initDirs,
  savePrivateKey,
  loadPrivateKey,
  savePublicKey,
  loadPublicKey,
  saveConfig,
  loadConfig,
  getRepoDir,
  getSecretsFile,
  getRecipientsFile,
  getMetaFile,
  listRepos,
  repoExists,
  createRepoDir,
  deleteRepo,
  saveRecipients,
  loadRecipients,
  saveMeta,
  loadMeta,
  saveSecrets,
  loadSecrets,
  // Per-repo storage
  getLocalVaultDir,
  hasLocalVault,
  initLocalVault,
  getLocalSecretsFile,
  getLocalRecipientsFile,
  getLocalMetaFile,
  saveLocalSecrets,
  loadLocalSecrets,
  saveLocalRecipients,
  loadLocalRecipients,
  saveLocalMeta,
  loadLocalMeta,
  deleteLocalVault,
  getRepoNameFromDir
};
