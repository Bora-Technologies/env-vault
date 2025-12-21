/**
 * Pull wrapped DEKs from Supabase backend
 *
 * This syncs wrapped DEKs from the backend to local storage.
 * Useful when someone has shared access with you via the backend.
 */
const vault = require('../lib/vault');
const supabase = require('../lib/supabase');
const crypto = require('@env-vault/crypto');

async function pull() {
  console.log('\n📥 Pull from Backend\n');

  // Check if linked to account
  if (!supabase.isLinked()) {
    console.error('Not linked to an account.');
    console.error('Run: env-vault device link');
    process.exit(1);
  }

  const account = supabase.getLinkedAccount();
  console.log(`Account: ${account.email}`);
  console.log('');

  try {
    // Get repos we have access to
    console.log('Fetching repos...');
    const repos = await supabase.getMyRepos();

    if (!repos || repos.length === 0) {
      console.log('No repos found on backend.');
      console.log('');
      console.log('To add a repo, run:');
      console.log('  cd /path/to/project');
      console.log('  env-vault init-repo');
      console.log('  env-vault push');
      return;
    }

    console.log(`Found ${repos.length} repo(s):\n`);

    for (const repo of repos) {
      console.log(`  ${repo.name}`);
      console.log(`    Role: ${repo.role}`);
      console.log(`    DEK Version: ${repo.dek_version}`);
      console.log(`    Owner: ${repo.owner_email}`);
      console.log('');
    }

    console.log('---');
    console.log('');
    console.log('To access a repo\'s secrets:');
    console.log('  1. Clone the project containing .env-vault/');
    console.log('  2. Run: env-vault get .');
    console.log('');
    console.log('Or to fetch secrets from backend cache:');
    console.log('  env-vault get --remote <repo-name>');
    console.log('');
  } catch (error) {
    console.error('\n❌ Pull failed:', error.message);
    process.exit(1);
  }
}

module.exports = pull;
