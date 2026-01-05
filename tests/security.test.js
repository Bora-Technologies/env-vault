/**
 * Security tests for env-vault
 *
 * Run with: npm test
 *
 * These tests verify:
 * 1. Crypto correctness (encrypt/decrypt roundtrip, tamper detection)
 * 2. Permission enforcement
 * 3. Secret handling hygiene
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('../packages/crypto');

// Test utilities
const TEST_DIR = path.join(os.tmpdir(), `env-vault-test-${Date.now()}`);

function setup() {
  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }
}

function cleanup() {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
}

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    return true;
  } catch (err) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${err.message}`);
    return false;
  }
}

async function asyncTest(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    return true;
  } catch (err) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${err.message}`);
    return false;
  }
}

// ============================================
// Crypto Tests
// ============================================

console.log('\n--- Crypto Tests ---\n');

let cryptoTestsPassed = 0;
let cryptoTestsFailed = 0;

// Test AES-256-GCM encrypt/decrypt roundtrip
if (test('AES-256-GCM roundtrip', () => {
  const key = crypto.generateDEK();
  const plaintext = 'API_KEY=sk-1234567890abcdef\nDB_URL=postgres://localhost';

  const encrypted = crypto.encrypt(plaintext, key);
  const decrypted = crypto.decrypt(encrypted, key);

  assert.strictEqual(decrypted.toString('utf8'), plaintext, 'Decrypted text should match original');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test AES-256-GCM tamper detection
if (test('AES-256-GCM tamper detection', () => {
  const key = crypto.generateDEK();
  const plaintext = 'SECRET=very-sensitive-data';

  const encrypted = crypto.encrypt(plaintext, key);

  // Tamper with the ciphertext
  encrypted[20] ^= 0xff;

  let caught = false;
  try {
    crypto.decrypt(encrypted, key);
  } catch (err) {
    caught = true;
  }

  assert.strictEqual(caught, true, 'Tampered ciphertext should fail decryption');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test AES-256-GCM wrong key detection
if (test('AES-256-GCM wrong key detection', () => {
  const key1 = crypto.generateDEK();
  const key2 = crypto.generateDEK();
  const plaintext = 'SECRET=data';

  const encrypted = crypto.encrypt(plaintext, key1);

  let caught = false;
  try {
    crypto.decrypt(encrypted, key2);
  } catch (err) {
    caught = true;
  }

  assert.strictEqual(caught, true, 'Wrong key should fail decryption');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test IV uniqueness (encryption should produce different ciphertext)
if (test('AES-256-GCM IV uniqueness', () => {
  const key = crypto.generateDEK();
  const plaintext = 'SECRET=same-data';

  const encrypted1 = crypto.encrypt(plaintext, key);
  const encrypted2 = crypto.encrypt(plaintext, key);

  assert.notStrictEqual(
    encrypted1.toString('hex'),
    encrypted2.toString('hex'),
    'Same plaintext should produce different ciphertext (random IV)'
  );
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test X25519 key wrapping roundtrip
if (test('X25519 key wrapping roundtrip', () => {
  const recipientKeypair = crypto.generateKeypair();
  const dek = crypto.generateDEK();

  const sealed = crypto.sealBox(dek, recipientKeypair.publicKey);
  const opened = crypto.openBox(sealed, recipientKeypair.secretKey);

  assert.strictEqual(
    opened.toString('hex'),
    dek.toString('hex'),
    'Unwrapped DEK should match original'
  );
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test X25519 wrong key detection
if (test('X25519 wrong key detection', () => {
  const keypair1 = crypto.generateKeypair();
  const keypair2 = crypto.generateKeypair();
  const dek = crypto.generateDEK();

  const sealed = crypto.sealBox(dek, keypair1.publicKey);

  let caught = false;
  try {
    crypto.openBox(sealed, keypair2.secretKey);
  } catch (err) {
    caught = true;
  }

  assert.strictEqual(caught, true, 'Wrong secret key should fail decryption');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test fingerprint consistency
if (test('Fingerprint consistency', () => {
  const keypair = crypto.generateKeypair();

  const fp1 = crypto.getFingerprint(keypair.publicKey);
  const fp2 = crypto.getFingerprint(keypair.publicKey);

  assert.strictEqual(fp1, fp2, 'Same public key should produce same fingerprint');
  assert.strictEqual(fp1.length, 16, 'Fingerprint should be 16 hex characters');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// Test fingerprint uniqueness
if (test('Fingerprint uniqueness', () => {
  const keypair1 = crypto.generateKeypair();
  const keypair2 = crypto.generateKeypair();

  const fp1 = crypto.getFingerprint(keypair1.publicKey);
  const fp2 = crypto.getFingerprint(keypair2.publicKey);

  assert.notStrictEqual(fp1, fp2, 'Different keys should have different fingerprints');
})) cryptoTestsPassed++; else cryptoTestsFailed++;

// ============================================
// KDF Tests
// ============================================

console.log('\n--- KDF Tests ---\n');

let kdfTestsPassed = 0;
let kdfTestsFailed = 0;

(async () => {
  // Test scrypt key derivation
  if (await asyncTest('Scrypt key derivation', async () => {
    const password = 'test-password-123';
    const salt = crypto.generateSalt();

    const key = await crypto.deriveKey(password, salt);

    assert.strictEqual(key.length, 32, 'Derived key should be 32 bytes');
  })) kdfTestsPassed++; else kdfTestsFailed++;

  // Test scrypt determinism (same password + salt = same key)
  if (await asyncTest('Scrypt determinism', async () => {
    const password = 'test-password-456';
    const salt = crypto.generateSalt();

    const key1 = await crypto.deriveKey(password, salt);
    const key2 = await crypto.deriveKey(password, salt);

    assert.strictEqual(
      key1.toString('hex'),
      key2.toString('hex'),
      'Same password and salt should produce same key'
    );
  })) kdfTestsPassed++; else kdfTestsFailed++;

  // Test scrypt salt sensitivity
  if (await asyncTest('Scrypt salt sensitivity', async () => {
    const password = 'test-password-789';
    const salt1 = crypto.generateSalt();
    const salt2 = crypto.generateSalt();

    const key1 = await crypto.deriveKey(password, salt1);
    const key2 = await crypto.deriveKey(password, salt2);

    assert.notStrictEqual(
      key1.toString('hex'),
      key2.toString('hex'),
      'Different salts should produce different keys'
    );
  })) kdfTestsPassed++; else kdfTestsFailed++;

  // Test hardened parameters
  if (await asyncTest('Scrypt uses hardened parameters', async () => {
    assert.ok(
      crypto.SCRYPT_CONFIG.N >= 131072,
      `N should be >= 2^17 (got ${crypto.SCRYPT_CONFIG.N})`
    );
  })) kdfTestsPassed++; else kdfTestsFailed++;

  // ============================================
  // Permission Tests
  // ============================================

  console.log('\n--- Permission Tests ---\n');

  setup();

  let permTestsPassed = 0;
  let permTestsFailed = 0;

  // Test secure file write
  const vault = require('../lib/vault');

  if (test('secureWriteFileSync creates 0600 files', () => {
    const testFile = path.join(TEST_DIR, 'secure-test.txt');
    vault.secureWriteFileSync(testFile, 'test content');

    const stats = fs.statSync(testFile);
    const mode = stats.mode & 0o777;

    assert.strictEqual(mode, 0o600, `File should be 0600 (got ${mode.toString(8)})`);
  })) permTestsPassed++; else permTestsFailed++;

  // Test secure directory creation
  if (test('secureCreateDir creates 0700 directories', () => {
    const testDir = path.join(TEST_DIR, 'secure-dir');
    vault.secureCreateDir(testDir);

    const stats = fs.statSync(testDir);
    const mode = stats.mode & 0o777;

    assert.strictEqual(mode, 0o700, `Directory should be 0700 (got ${mode.toString(8)})`);
  })) permTestsPassed++; else permTestsFailed++;

  // Test atomic write (file should exist after write)
  if (test('Atomic write creates complete file', () => {
    const testFile = path.join(TEST_DIR, 'atomic-test.txt');
    const content = 'line1\nline2\nline3';

    vault.secureWriteFileSync(testFile, content);
    const readBack = fs.readFileSync(testFile, 'utf8');

    assert.strictEqual(readBack, content, 'File content should match');
  })) permTestsPassed++; else permTestsFailed++;

  // Test path traversal prevention
  if (test('validateRepoName prevents path traversal', () => {
    const maliciousNames = [
      '../etc/passwd',
      '..\\windows\\system32',
      'repo/../../../etc',
      '..',
      '.',
    ];

    for (const name of maliciousNames) {
      let caught = false;
      try {
        vault.validateRepoName(name);
      } catch (err) {
        caught = true;
      }
      assert.strictEqual(caught, true, `Should reject "${name}"`);
    }
  })) permTestsPassed++; else permTestsFailed++;

  // Test valid repo names
  if (test('validateRepoName accepts valid names', () => {
    const validNames = [
      'my-project',
      'project123',
      'my_project',
      'project.name'
    ];

    for (const name of validNames) {
      const result = vault.validateRepoName(name);
      assert.strictEqual(result, name, `Should accept "${name}"`);
    }
  })) permTestsPassed++; else permTestsFailed++;

  cleanup();

  // ============================================
  // Summary
  // ============================================

  console.log('\n--- Test Summary ---\n');

  const totalPassed = cryptoTestsPassed + kdfTestsPassed + permTestsPassed;
  const totalFailed = cryptoTestsFailed + kdfTestsFailed + permTestsFailed;

  console.log(`Crypto tests: ${cryptoTestsPassed} passed, ${cryptoTestsFailed} failed`);
  console.log(`KDF tests: ${kdfTestsPassed} passed, ${kdfTestsFailed} failed`);
  console.log(`Permission tests: ${permTestsPassed} passed, ${permTestsFailed} failed`);
  console.log(`\nTotal: ${totalPassed} passed, ${totalFailed} failed\n`);

  if (totalFailed > 0) {
    process.exit(1);
  }
})();
