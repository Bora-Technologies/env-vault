/**
 * Supabase client for CLI
 * Handles account auth and device management
 */
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Config file location
const CONFIG_DIR = path.join(os.homedir(), '.env-vault');
const ACCOUNT_FILE = path.join(CONFIG_DIR, 'account.json');

let supabase = null;

/**
 * Initialize Supabase client
 * Reads URL and key from environment or config
 */
function getClient() {
  if (supabase) return supabase;

  const url = process.env.ENV_VAULT_SUPABASE_URL || getAccountConfig().supabaseUrl;
  const key = process.env.ENV_VAULT_SUPABASE_ANON_KEY || getAccountConfig().supabaseKey;

  if (!url || !key) {
    throw new Error(
      'Supabase not configured. Set ENV_VAULT_SUPABASE_URL and ENV_VAULT_SUPABASE_ANON_KEY environment variables.'
    );
  }

  supabase = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return supabase;
}

/**
 * Load account config from disk
 */
function getAccountConfig() {
  try {
    if (fs.existsSync(ACCOUNT_FILE)) {
      return JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Failed to load account config:', e.message);
  }
  return {};
}

/**
 * Save account config to disk
 */
function saveAccountConfig(config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNT_FILE, JSON.stringify(config, null, 2));
}

/**
 * Check if connected to account
 */
function isLinked() {
  const config = getAccountConfig();
  return !!(config.deviceId && config.userId);
}

/**
 * Get linked account info
 */
function getLinkedAccount() {
  return getAccountConfig();
}

/**
 * Verify OTP and link device to account
 * @param {string} email - User's email
 * @param {string} otpCode - 6-digit OTP from mobile app
 * @param {string} fingerprint - Device fingerprint
 * @param {string} publicKey - Base64 public key
 * @param {string} label - Device label
 */
async function verifyAndLinkDevice(email, otpCode, fingerprint, publicKey, label) {
  const client = getClient();

  // Call the verify_device_otp function
  const { data, error } = await client.rpc('verify_device_otp', {
    p_user_email: email,
    p_otp_code: otpCode,
  });

  if (error) throw error;

  const result = data[0];
  if (!result.success) {
    throw new Error(result.message);
  }

  // Save account config
  saveAccountConfig({
    ...getAccountConfig(),
    userId: result.user_id,
    deviceId: result.device_id,
    email: email,
    fingerprint: fingerprint,
    linkedAt: new Date().toISOString(),
  });

  return result;
}

/**
 * Get user's devices by email (for sharing)
 */
async function getUserDevicesByEmail(email) {
  const client = getClient();

  const { data, error } = await client.rpc('get_user_devices_by_email', {
    p_email: email,
  });

  if (error) throw error;
  return data;
}

/**
 * Get repos user has access to
 */
async function getMyRepos() {
  const account = getLinkedAccount();
  if (!account.userId) {
    throw new Error('Not linked to an account. Run: env-vault device link');
  }

  // We need to authenticate as the user to call this
  // For now, this requires the mobile app to have pushed data
  const client = getClient();
  const { data, error } = await client.rpc('get_my_repos');
  if (error) throw error;
  return data;
}

/**
 * Get wrapped DEK for a repo
 */
async function getWrappedDek(repoId, fingerprint) {
  const client = getClient();

  const { data, error } = await client.rpc('get_wrapped_dek', {
    p_repo_id: repoId,
    p_device_fingerprint: fingerprint,
  });

  if (error) throw error;
  return data[0];
}

/**
 * Create or update a repo
 */
async function upsertRepo(name) {
  const account = getLinkedAccount();
  const client = getClient();

  const { data, error } = await client
    .from('repos')
    .upsert({ name, owner_id: account.userId }, { onConflict: 'name,owner_id' })
    .select()
    .single();

  if (error) throw error;
  return data;
}

/**
 * Upload wrapped DEKs for a repo
 */
async function uploadWrappedDeks(repoId, wrappedDeks, dekVersion) {
  const client = getClient();

  // Transform to database format
  const records = wrappedDeks.map((dek) => ({
    repo_id: repoId,
    device_id: dek.deviceId,
    wrapped_dek: dek.wrappedDek,
    dek_version: dekVersion,
  }));

  const { error } = await client.from('wrapped_deks').upsert(records, {
    onConflict: 'repo_id,device_id',
  });

  if (error) throw error;
}

/**
 * Upload encrypted secrets cache
 */
async function uploadSecretsCache(repoId, encryptedSecrets, dekVersion) {
  const client = getClient();

  const { error } = await client.from('secrets_cache').upsert(
    {
      repo_id: repoId,
      encrypted_secrets: encryptedSecrets,
      dek_version: dekVersion,
    },
    { onConflict: 'repo_id' }
  );

  if (error) throw error;
}

/**
 * Get cached secrets for a repo
 */
async function getCachedSecrets(repoId) {
  const client = getClient();

  const { data, error } = await client
    .from('secrets_cache')
    .select('encrypted_secrets, dek_version')
    .eq('repo_id', repoId)
    .single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}

/**
 * Share repo access with another user
 */
async function shareRepoAccess(repoId, userId, role, wrappedDeks) {
  const client = getClient();

  // Add repo access
  const { error: accessError } = await client.from('repo_access').upsert(
    {
      repo_id: repoId,
      user_id: userId,
      role: role,
    },
    { onConflict: 'repo_id,user_id' }
  );

  if (accessError) throw accessError;

  // Add wrapped DEKs for user's devices
  if (wrappedDeks && wrappedDeks.length > 0) {
    await uploadWrappedDeks(repoId, wrappedDeks);
  }
}

/**
 * Unlink device from account
 */
function unlinkDevice() {
  const config = getAccountConfig();
  delete config.userId;
  delete config.deviceId;
  delete config.email;
  delete config.linkedAt;
  saveAccountConfig(config);
}

module.exports = {
  getClient,
  getAccountConfig,
  saveAccountConfig,
  isLinked,
  getLinkedAccount,
  verifyAndLinkDevice,
  getUserDevicesByEmail,
  getMyRepos,
  getWrappedDek,
  upsertRepo,
  uploadWrappedDeks,
  uploadSecretsCache,
  getCachedSecrets,
  shareRepoAccess,
  unlinkDevice,
};
