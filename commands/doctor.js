const fs = require('fs');
const path = require('path');
const vault = require('../lib/vault');
const crypto = require('@env-vault/crypto');

/**
 * Check if file has secure permissions (owner-only)
 * @param {string} filePath - File path to check
 * @returns {{secure: boolean, mode: string|null, message: string}}
 */
function checkPermissions(filePath) {
  if (!fs.existsSync(filePath)) {
    return { secure: true, mode: null, message: 'File does not exist' };
  }

  const stats = fs.statSync(filePath);
  const mode = stats.mode & 0o777;
  const modeStr = mode.toString(8).padStart(3, '0');

  if (stats.isDirectory()) {
    if (mode & 0o077) {
      return {
        secure: false,
        mode: modeStr,
        message: `Directory is accessible by group/others (${modeStr})`
      };
    }
    return { secure: true, mode: modeStr, message: 'OK' };
  }

  if (mode & 0o077) {
    return {
      secure: false,
      mode: modeStr,
      message: `File is readable by group/others (${modeStr})`
    };
  }
  return { secure: true, mode: modeStr, message: 'OK' };
}

/**
 * Fix file permissions to be owner-only
 * @param {string} filePath - File path to fix
 * @param {boolean} isDir - Whether this is a directory
 */
function fixPermissions(filePath, isDir) {
  if (fs.existsSync(filePath)) {
    const mode = isDir ? vault.DIR_MODE : vault.FILE_MODE;
    fs.chmodSync(filePath, mode);
  }
}

async function doctor(options = {}) {
  console.log('\n--- env-vault Security Check ---\n');

  const issues = [];
  const warnings = [];
  let fixedCount = 0;

  // Check if vault is initialized
  if (!vault.isInitialized()) {
    console.log('Vault not initialized. Run: env-vault init\n');
    return;
  }

  // 1. Check directory permissions
  console.log('Checking vault directories...');
  const dirs = [
    vault.VAULT_DIR,
    vault.IDENTITY_DIR,
    vault.REPOS_DIR
  ];

  for (const dir of dirs) {
    const result = checkPermissions(dir);
    const shortPath = dir.replace(process.env.HOME, '~');

    if (!result.secure) {
      if (options.fix) {
        fixPermissions(dir, true);
        console.log(`  [FIXED] ${shortPath}: ${result.mode} -> 700`);
        fixedCount++;
      } else {
        console.log(`  [FAIL] ${shortPath}: ${result.message}`);
        issues.push({ path: dir, type: 'directory', issue: result.message });
      }
    } else if (result.mode) {
      console.log(`  [OK] ${shortPath}: ${result.mode}`);
    }
  }

  // 2. Check key file permissions
  console.log('\nChecking key files...');
  const keyFiles = [
    { path: path.join(vault.IDENTITY_DIR, 'private.key'), name: 'Private key' },
    { path: path.join(vault.IDENTITY_DIR, 'salt'), name: 'Salt' },
    { path: path.join(vault.IDENTITY_DIR, 'public.key'), name: 'Public key' },
    { path: path.join(vault.VAULT_DIR, 'config.json'), name: 'Config' }
  ];

  for (const file of keyFiles) {
    const result = checkPermissions(file.path);
    const shortPath = file.path.replace(process.env.HOME, '~');

    if (!result.secure && result.mode !== null) {
      if (options.fix) {
        fixPermissions(file.path, false);
        console.log(`  [FIXED] ${file.name}: ${result.mode} -> 600`);
        fixedCount++;
      } else {
        console.log(`  [FAIL] ${file.name}: ${result.message}`);
        issues.push({ path: file.path, type: 'file', issue: result.message });
      }
    } else if (result.mode) {
      console.log(`  [OK] ${file.name}: ${result.mode}`);
    }
  }

  // 3. Check local vault if present
  if (vault.hasLocalVault()) {
    console.log('\nChecking local .env-vault...');
    const localDir = vault.getLocalVaultDir();
    const localResult = checkPermissions(localDir);

    if (!localResult.secure) {
      if (options.fix) {
        fixPermissions(localDir, true);
        console.log(`  [FIXED] .env-vault/: ${localResult.mode} -> 700`);
        fixedCount++;
      } else {
        console.log(`  [FAIL] .env-vault/: ${localResult.message}`);
        issues.push({ path: localDir, type: 'directory', issue: localResult.message });
      }
    } else if (localResult.mode) {
      console.log(`  [OK] .env-vault/: ${localResult.mode}`);
    }

    // Check local files
    const localFiles = [
      vault.getLocalSecretsFile(),
      vault.getLocalRecipientsFile()
    ];

    for (const filePath of localFiles) {
      if (fs.existsSync(filePath)) {
        const result = checkPermissions(filePath);
        const fileName = path.basename(filePath);

        if (!result.secure) {
          if (options.fix) {
            fixPermissions(filePath, false);
            console.log(`  [FIXED] ${fileName}: ${result.mode} -> 600`);
            fixedCount++;
          } else {
            console.log(`  [FAIL] ${fileName}: ${result.message}`);
            issues.push({ path: filePath, type: 'file', issue: result.message });
          }
        } else {
          console.log(`  [OK] ${fileName}: ${result.mode}`);
        }
      }
    }
  }

  // 4. Check for plaintext .env files that might be exposed
  console.log('\nChecking for plaintext .env files...');
  const envPatterns = ['.env', '.env.local', '.env.development', '.env.production'];
  let foundPlaintext = false;

  for (const pattern of envPatterns) {
    const envPath = path.join(process.cwd(), pattern);
    if (fs.existsSync(envPath)) {
      const stats = fs.statSync(envPath);
      const mode = (stats.mode & 0o777).toString(8).padStart(3, '0');

      if (stats.mode & 0o044) {
        console.log(`  [WARN] ${pattern} is readable by others (${mode})`);
        warnings.push(`${pattern} has loose permissions`);
      } else {
        console.log(`  [OK] ${pattern}: ${mode}`);
      }
      foundPlaintext = true;
    }
  }

  if (!foundPlaintext) {
    console.log('  No plaintext .env files in current directory');
  }

  // 5. Check crypto parameters
  console.log('\nChecking crypto configuration...');
  console.log(`  KDF: scrypt (N=${crypto.SCRYPT_CONFIG.N}, r=${crypto.SCRYPT_CONFIG.r}, p=${crypto.SCRYPT_CONFIG.p})`);

  if (crypto.SCRYPT_CONFIG.N < 131072) {
    console.log('  [WARN] KDF work factor below recommended minimum (2^17)');
    warnings.push('KDF parameters may be too weak');
  } else {
    console.log('  [OK] KDF work factor meets security recommendations');
  }

  // 6. Check for .gitignore protection
  console.log('\nChecking git safety...');
  const gitignorePath = path.join(process.cwd(), '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, 'utf8');
    if (gitignore.includes('.env')) {
      console.log('  [OK] .gitignore includes .env patterns');
    } else {
      console.log('  [WARN] .gitignore may not protect .env files');
      warnings.push('.gitignore should include .env patterns');
    }
  } else {
    console.log('  [WARN] No .gitignore found in current directory');
  }

  // Summary
  console.log('\n--- Summary ---\n');

  if (issues.length === 0 && warnings.length === 0) {
    console.log('All security checks passed!\n');
  } else {
    if (issues.length > 0) {
      console.log(`Critical issues: ${issues.length}`);
      if (!options.fix) {
        console.log('Run "env-vault doctor --fix" to automatically fix permission issues.\n');
      }
    }
    if (warnings.length > 0) {
      console.log(`Warnings: ${warnings.length}`);
      for (const warning of warnings) {
        console.log(`  - ${warning}`);
      }
      console.log();
    }
  }

  if (options.fix && fixedCount > 0) {
    console.log(`Fixed ${fixedCount} issue(s).\n`);
  }

  // Return status for programmatic use
  return {
    issues,
    warnings,
    fixed: fixedCount
  };
}

module.exports = doctor;
