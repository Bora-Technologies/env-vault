/**
 * Device management commands
 *
 * Commands:
 *   env-vault device link     - Link device to account via OTP
 *   env-vault device status   - Show linked account status
 *   env-vault device unlink   - Unlink device from account
 */
const inquirer = require('inquirer');
const vault = require('../lib/vault');
const supabase = require('../lib/supabase');
const crypto = require('@env-vault/crypto');

/**
 * Link device to account using OTP from mobile app
 */
async function link() {
  console.log('\n🔗 Link Device to Account\n');

  // Check if already linked
  if (supabase.isLinked()) {
    const account = supabase.getLinkedAccount();
    console.log(`Already linked to account: ${account.email}`);

    const { confirm } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'confirm',
        message: 'Do you want to unlink and link to a different account?',
        default: false,
      },
    ]);

    if (!confirm) {
      return;
    }
    supabase.unlinkDevice();
  }

  // Check if vault is initialized
  if (!vault.isInitialized()) {
    console.log('Vault not initialized. Please run: env-vault init');
    process.exit(1);
  }

  // Get identity info
  const publicKey = vault.loadPublicKey();
  const fingerprint = crypto.getFingerprint(publicKey);
  const config = vault.loadConfig();
  const publicKeyBase64 = publicKey.toString('base64');

  console.log('Your device fingerprint:', fingerprint);
  console.log('');

  // Prompt for email and OTP
  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'email',
      message: 'Enter your account email:',
      validate: (input) => {
        if (!input || !input.includes('@')) {
          return 'Please enter a valid email address';
        }
        return true;
      },
    },
    {
      type: 'input',
      name: 'otp',
      message: 'Enter the 6-digit code from your mobile app:',
      validate: (input) => {
        if (!/^\d{6}$/.test(input)) {
          return 'Please enter a 6-digit code';
        }
        return true;
      },
    },
  ]);

  console.log('\nVerifying code...');

  try {
    const result = await supabase.verifyAndLinkDevice(
      answers.email,
      answers.otp,
      fingerprint,
      publicKeyBase64,
      config.deviceLabel || 'CLI Device'
    );

    console.log('\n✅ Device linked successfully!');
    console.log(`   Account: ${answers.email}`);
    console.log(`   Device ID: ${result.device_id}`);
    console.log('');
    console.log('You can now:');
    console.log('  - Push secrets to the cloud: env-vault push');
    console.log('  - Share repos by email: env-vault share <email>');
    console.log('');
  } catch (error) {
    console.error('\n❌ Failed to link device:', error.message);
    console.log('');
    console.log('Make sure:');
    console.log('  1. You generated the code on your mobile app');
    console.log('  2. The code has not expired (5 minutes)');
    console.log('  3. You entered the correct email');
    process.exit(1);
  }
}

/**
 * Show linked account status
 */
async function status() {
  console.log('\n📱 Device Status\n');

  if (!vault.isInitialized()) {
    console.log('Vault not initialized. Please run: env-vault init');
    process.exit(1);
  }

  const publicKey = vault.loadPublicKey();
  const fingerprint = crypto.getFingerprint(publicKey);
  const config = vault.loadConfig();

  console.log('Device Label:', config.deviceLabel || 'Unknown');
  console.log('Fingerprint:', fingerprint);
  console.log('Created:', config.createdAt || 'Unknown');
  console.log('');

  if (supabase.isLinked()) {
    const account = supabase.getLinkedAccount();
    console.log('✅ Linked to Account');
    console.log('   Email:', account.email);
    console.log('   Linked:', account.linkedAt);
  } else {
    console.log('❌ Not linked to any account');
    console.log('   Run: env-vault device link');
  }
  console.log('');
}

/**
 * Unlink device from account
 */
async function unlink() {
  console.log('\n🔓 Unlink Device\n');

  if (!supabase.isLinked()) {
    console.log('Device is not linked to any account.');
    return;
  }

  const account = supabase.getLinkedAccount();

  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: `Unlink from account ${account.email}?`,
      default: false,
    },
  ]);

  if (!confirm) {
    console.log('Cancelled.');
    return;
  }

  supabase.unlinkDevice();
  console.log('✅ Device unlinked successfully.');
  console.log('');
  console.log('Note: Your local vault and identity are preserved.');
  console.log('You can link to an account again with: env-vault device link');
  console.log('');
}

module.exports = { link, status, unlink };
