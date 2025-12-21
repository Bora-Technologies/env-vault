#!/usr/bin/env node

const path = require('path');
const os = require('os');

// Load .env from multiple locations (first found wins)
require('dotenv').config(); // current directory
require('dotenv').config({ path: path.join(os.homedir(), '.env-vault', '.env') }); // ~/.env-vault/.env
require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); // CLI package directory

const fs = require('fs');
const { Command } = require('commander');
const program = new Command();

program
  .name('env-vault')
  .description('Secure .env file management with sharing and sync')
  .version(require('../package.json').version, '-v, --version', 'Output the version number')
  .helpOption('-h, --help', 'Display help for command');

// init command
program
  .command('init')
  .description('Initialize a new vault with a master password')
  .option('-l, --label <label>', 'Label for this device (e.g., "MacBook Pro")')
  .action(async (options) => {
    const init = require('../commands/init');
    await init(options.label);
  });

// identity show command (as subcommand pattern)
const identityCmd = program
  .command('identity')
  .description('Manage your identity');

identityCmd
  .command('show')
  .description('Show your public key')
  .action(() => {
    const identity = require('../commands/identity');
    identity.show();
  });

// Also make "identity" without subcommand show the key (convenience)
identityCmd.action(() => {
  const identity = require('../commands/identity');
  identity.show();
});

// init-repo command
program
  .command('init-repo')
  .description('Initialize .env-vault in current project directory')
  .argument('[envFile]', 'Path to .env file to encrypt')
  .action(async (envFile) => {
    const initRepo = require('../commands/init-repo');
    await initRepo(envFile);
  });

// add command
program
  .command('add <repo>')
  .description('Add or update secrets for a repository')
  .argument('[file]', 'Path to .env file (reads from stdin if not provided)')
  .option('--local', 'Use local .env-vault/ in current directory')
  .action(async (repo, file, options) => {
    let repoName = repo;
    let filePath = file;
    if (!filePath && repo && fs.existsSync(repo) && fs.statSync(repo).isFile()) {
      filePath = repo;
      repoName = path.basename(process.cwd());
      console.log(`Using repo name "${repoName}" and reading from ${filePath}`);
    }
    const add = require('../commands/add');
    await add(repoName, filePath, options);
  });

// get command
program
  .command('get [repo]')
  .description('Get decrypted secrets for a repository (use "." for local .env-vault)')
  .argument('[file]', 'Path to write .env file (outputs to stdout if not provided)')
  .option('--local', 'Use local .env-vault/ in current directory')
  .action(async (repo, file, options) => {
    const get = require('../commands/get');
    await get(repo || '.', file, options);
  });

// list command
program
  .command('list')
  .alias('ls')
  .description('List all repositories')
  .action(() => {
    const list = require('../commands/list');
    list();
  });

// rm command
program
  .command('rm <repo>')
  .description('Remove a repository')
  .option('-f, --force', 'Force removal without confirmation')
  .action(async (repo, options) => {
    const rm = require('../commands/rm');
    await rm(repo, options);
  });

// share command
program
  .command('share <repo> <pubkey>')
  .description('Share a repository with a public key')
  .option('-l, --label <label>', 'Label for this recipient (e.g., "John\'s laptop")')
  .action(async (repo, pubkey, options) => {
    const share = require('../commands/share');
    await share(repo, pubkey, options.label);
  });

// revoke command
program
  .command('revoke <repo> <fingerprint>')
  .description('Revoke access to a repository')
  .action(async (repo, fingerprint) => {
    const revoke = require('../commands/revoke');
    await revoke(repo, fingerprint);
  });

// recipients command
program
  .command('recipients [repo]')
  .description('List recipients who have access to a repository')
  .action((repo) => {
    const recipients = require('../commands/recipients');
    recipients(repo);
  });

// sync command
program
  .command('sync')
  .description('Sync vault with remote git repository')
  .action(async () => {
    const sync = require('../commands/sync');
    await sync();
  });

// clone command
program
  .command('clone <git-url>')
  .description('Clone an existing vault from a git repository')
  .action(async (gitUrl) => {
    const clone = require('../commands/clone');
    await clone(gitUrl);
  });

// edit command
program
  .command('edit <repo>')
  .description('Edit secrets in your default editor')
  .action(async (repo) => {
    const edit = require('../commands/edit');
    await edit(repo);
  });

// migrate command
program
  .command('migrate')
  .description('Migrate repos from central vault to per-project storage')
  .action(async () => {
    const migrate = require('../commands/migrate');
    await migrate();
  });

// reset command
program
  .command('reset')
  .description('Delete vault and start fresh (use if you forgot password)')
  .option('-f, --force', 'Skip confirmation prompt')
  .action(async (options) => {
    const reset = require('../commands/reset');
    await reset(options);
  });

// Cloud sync commands (requires backend setup - coming soon)
// To enable, set ENV_VAULT_SUPABASE_URL and ENV_VAULT_SUPABASE_ANON_KEY

// // push command
// program
//   .command('push')
//   .description('Push local .env-vault to backend for mobile access')
//   .action(async () => {
//     const push = require('../commands/push');
//     await push();
//   });

// // pull command
// program
//   .command('pull')
//   .description('Pull and list repos from backend')
//   .action(async () => {
//     const pull = require('../commands/pull');
//     await pull();
//   });

// device command (requires backend setup)
// const deviceCmd = program
//   .command('device')
//   .description('Manage device and account linking');

// deviceCmd
//   .command('link')
//   .description('Link this device to your account via OTP')
//   .action(async () => {
//     const device = require('../commands/device');
//     await device.link();
//   });

// deviceCmd
//   .command('status')
//   .description('Show device and account status')
//   .action(async () => {
//     const device = require('../commands/device');
//     await device.status();
//   });

// deviceCmd
//   .command('unlink')
//   .description('Unlink device from account')
//   .action(async () => {
//     const device = require('../commands/device');
//     await device.unlink();
//   });

// // Default device action shows status
// deviceCmd.action(async () => {
//   const device = require('../commands/device');
//   await device.status();
// });

program.parse();
