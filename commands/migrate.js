/**
 * Migrate repos from central vault to per-repo storage
 *
 * This command helps users transition from the old centralized vault
 * (~/.env-vault/repos/) to the new per-repo model (.env-vault/ in projects)
 */
const fs = require('fs');
const path = require('path');
const inquirer = require('inquirer');
const vault = require('../lib/vault');

async function migrate() {
  console.log('\n📦 Migrate to Per-Repo Storage\n');

  // Check if central vault has any repos
  const centralRepos = vault.listRepos();

  if (centralRepos.length === 0) {
    console.log('No repos found in central vault (~/.env-vault/repos/)');
    console.log('');
    console.log('To create a new per-repo vault:');
    console.log('  cd /path/to/project');
    console.log('  env-vault init-repo');
    return;
  }

  console.log(`Found ${centralRepos.length} repo(s) in central vault:\n`);

  for (const repo of centralRepos) {
    console.log(`  • ${repo}`);
  }
  console.log('');

  const { proceed } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'proceed',
      message: 'Migrate these repos to per-project .env-vault/ directories?',
      default: true,
    },
  ]);

  if (!proceed) {
    console.log('Aborted.');
    return;
  }

  console.log('');

  // Process each repo
  const migrated = [];
  const skipped = [];

  for (const repoName of centralRepos) {
    console.log(`\n📁 ${repoName}`);

    const { projectPath } = await inquirer.prompt([
      {
        type: 'input',
        name: 'projectPath',
        message: `  Enter project directory path (or skip):`,
        default: '',
      },
    ]);

    if (!projectPath || projectPath.toLowerCase() === 'skip') {
      skipped.push(repoName);
      console.log('  Skipped.');
      continue;
    }

    const absolutePath = path.resolve(projectPath);

    // Check if directory exists
    if (!fs.existsSync(absolutePath)) {
      console.log(`  Directory not found: ${absolutePath}`);

      const { create } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'create',
          message: '  Create this directory?',
          default: false,
        },
      ]);

      if (create) {
        fs.mkdirSync(absolutePath, { recursive: true });
      } else {
        skipped.push(repoName);
        console.log('  Skipped.');
        continue;
      }
    }

    // Check if already has .env-vault
    const targetDir = path.join(absolutePath, '.env-vault');
    if (fs.existsSync(targetDir)) {
      console.log(`  Warning: .env-vault already exists in ${absolutePath}`);

      const { overwrite } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'overwrite',
          message: '  Overwrite existing .env-vault?',
          default: false,
        },
      ]);

      if (!overwrite) {
        skipped.push(repoName);
        console.log('  Skipped.');
        continue;
      }
    }

    // Copy files
    try {
      const sourceDir = vault.getRepoDir(repoName);

      // Create target directory
      fs.mkdirSync(targetDir, { recursive: true });

      // Copy secrets.enc
      const secretsSource = path.join(sourceDir, 'secrets.enc');
      const secretsTarget = path.join(targetDir, 'secrets.enc');
      if (fs.existsSync(secretsSource)) {
        fs.copyFileSync(secretsSource, secretsTarget);
      }

      // Copy recipients.json
      const recipientsSource = path.join(sourceDir, 'recipients.json');
      const recipientsTarget = path.join(targetDir, 'recipients.json');
      if (fs.existsSync(recipientsSource)) {
        fs.copyFileSync(recipientsSource, recipientsTarget);
      }

      // Copy meta.json if exists
      const metaSource = path.join(sourceDir, 'meta.json');
      const metaTarget = path.join(targetDir, 'meta.json');
      if (fs.existsSync(metaSource)) {
        fs.copyFileSync(metaSource, metaTarget);
      }

      // Create .gitignore
      const gitignorePath = path.join(targetDir, '.gitignore');
      const gitignoreContent = `# Never commit plaintext secrets
*.env
*.env.*
!*.enc
`;
      fs.writeFileSync(gitignorePath, gitignoreContent);

      migrated.push({ name: repoName, path: absolutePath });
      console.log(`  ✅ Migrated to ${targetDir}`);
    } catch (e) {
      console.error(`  ❌ Failed: ${e.message}`);
      skipped.push(repoName);
    }
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('\n📊 Migration Summary\n');

  if (migrated.length > 0) {
    console.log('Migrated:');
    for (const { name, path: p } of migrated) {
      console.log(`  ✅ ${name} → ${p}/.env-vault/`);
    }
    console.log('');
  }

  if (skipped.length > 0) {
    console.log('Skipped:');
    for (const name of skipped) {
      console.log(`  ⏭️  ${name}`);
    }
    console.log('');
  }

  // Ask about cleaning up central vault
  if (migrated.length > 0) {
    const { cleanup } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'cleanup',
        message: 'Remove migrated repos from central vault?',
        default: false,
      },
    ]);

    if (cleanup) {
      for (const { name } of migrated) {
        vault.deleteRepo(name);
        console.log(`  Removed ${name} from central vault`);
      }
      console.log('');
    } else {
      console.log('Original repos kept in central vault as backup.\n');
    }
  }

  console.log('Migration complete!\n');
  console.log('Next steps:');
  console.log('  1. cd into each project and verify: env-vault get .');
  console.log('  2. Commit .env-vault/ to git');
  console.log('  3. Push to backend for mobile: env-vault push');
  console.log('');
}

module.exports = migrate;
