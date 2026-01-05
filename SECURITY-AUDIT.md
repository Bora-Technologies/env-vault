# Security Audit Report: env-vault

**Audit Date:** 2026-01-05
**Version Audited:** 0.0.14
**Auditor:** Security Review

---

## Executive Summary

env-vault is a CLI tool for storing and sharing environment secrets using public-key cryptography. The cryptographic design is fundamentally sound (X25519 + AES-256-GCM + scrypt), but several implementation gaps create security risks for team usage.

**Critical Issues:** 2
**High Issues:** 4
**Medium Issues:** 5
**Low Issues:** 3

---

## Phase 1: Threat Model

### Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Master password | Critical | User memory only |
| Private key (encrypted) | Critical | `~/.env-vault/identity/private.key` |
| Private key (decrypted) | Critical | Memory during unlock |
| DEK (Data Encryption Key) | Critical | Memory during operations |
| Plaintext secrets | Critical | Memory, temp files (edit), output files |
| Encrypted secrets | Medium | `.env-vault/secrets.enc` |
| Public keys | Low | `.env-vault/recipients.json` |
| Salt | Low | `~/.env-vault/identity/salt` |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER'S MACHINE                          │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   User Memory   │    │   env-vault     │                     │
│  │ (master password)│───▶│    Process      │                     │
│  └─────────────────┘    │                 │                     │
│                         │  ┌───────────┐  │                     │
│                         │  │ Decrypted │  │                     │
│                         │  │ Secrets   │  │                     │
│                         │  │ (memory)  │  │                     │
│                         │  └───────────┘  │                     │
│                         └────────┬────────┘                     │
│                                  │                              │
│  ┌───────────────────────────────┼────────────────────────────┐ │
│  │              FILESYSTEM                                    │ │
│  │  ~/.env-vault/identity/private.key (ENCRYPTED)             │ │
│  │  ~/.env-vault/identity/salt                                │ │
│  │  ./.env-vault/secrets.enc (ENCRYPTED)                      │ │
│  │  /tmp/env-vault-*.env (PLAINTEXT - during edit)  ⚠️        │ │
│  │  ./.env (PLAINTEXT - after get)                            │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL (git, network)                      │
│  - Git repository (commits .env-vault/ - encrypted only)       │
│  - Shell history (may contain public keys)                      │
│  - Process list (visible command args)                          │
└─────────────────────────────────────────────────────────────────┘
```

### Attacker Types

| Attacker | Capability | Goals |
|----------|------------|-------|
| **Malicious local user** | Read files with weak permissions | Access secrets from other users |
| **Laptop thief** | Physical access, may extract disk | Decrypt private key, access secrets |
| **Compromised process** | Read /tmp, environment, memory | Steal decrypted secrets |
| **Supply chain attacker** | Modify npm package | Backdoor CLI, exfiltrate secrets |
| **Insider threat** | Valid recipient access | Retain access after revocation |
| **Network observer** | Intercept git traffic | Already mitigated (secrets encrypted) |

### Attack Paths (Prioritized)

1. **Read weak-permission private key** → Offline brute-force master password → Decrypt all secrets
2. **Read /tmp during edit** → Immediate plaintext access
3. **Compromise npm package** → Exfiltrate secrets on next run
4. **Shoulder surf master password** → Full access
5. **Access terminal scrollback** → Read secrets from `-p` output
6. **Exploit editor injection** → Code execution with secret access

---

## Phase 2: Security Findings

### CRITICAL SEVERITY

#### C1: Private Key File Has Default Permissions (World-Readable)

**File:** `lib/vault.js:78`
**Code:**
```javascript
function savePrivateKey(encryptedKey, salt) {
  fs.writeFileSync(PRIVATE_KEY_FILE, encryptedKey);  // No mode specified!
  fs.writeFileSync(SALT_FILE, salt);
}
```

**Impact:** On most Unix systems, `writeFileSync` without mode uses umask (typically 0644 = rw-r--r--). Any local user can read the encrypted private key and salt, enabling offline brute-force attacks.

**Exploit Scenario:**
```bash
# Attacker on same machine
cat /home/victim/.env-vault/identity/private.key > stolen.key
cat /home/victim/.env-vault/identity/salt > stolen.salt
# Offline brute-force with hashcat/john
```

**Fix:** Set mode 0600 on all sensitive files.

---

#### C2: Vault Directory Has Default Permissions

**File:** `lib/vault.js:67-69`
**Code:**
```javascript
function initDirs() {
  fs.mkdirSync(VAULT_DIR, { recursive: true });  // No mode specified!
  fs.mkdirSync(IDENTITY_DIR, { recursive: true });
  fs.mkdirSync(REPOS_DIR, { recursive: true });
}
```

**Impact:** Directory may be listable/readable by other users.

**Fix:** Set mode 0700 on vault directories.

---

### HIGH SEVERITY

#### H1: Temp File Contains Plaintext Secrets

**File:** `commands/edit.js:51-52, 80`
**Code:**
```javascript
const tempFile = path.join(os.tmpdir(), `env-vault-${repoName}-${Date.now()}.env`);
fs.writeFileSync(tempFile, content, { mode: 0o600 });
// ...
fs.unlinkSync(tempFile);  // Only called on success
```

**Issues:**
1. File in predictable location (`/tmp/env-vault-*`)
2. If editor crashes, process killed, or error thrown before unlink, file persists
3. File may be recovered from disk even after deletion
4. No secure overwrite before deletion

**Exploit Scenario:**
```bash
# Attacker monitors /tmp
watch -n 0.1 'ls /tmp/env-vault-* 2>/dev/null && cat /tmp/env-vault-*'
```

**Fix:** Use secure temp directory, try-finally cleanup, secure overwrite.

---

#### H2: KDF Parameters Too Weak for Offline Attack

**File:** `packages/crypto/kdf.js:7-12`
**Code:**
```javascript
const SCRYPT_CONFIG = {
  N: 16384,      // 2^14 - too low!
  r: 8,
  p: 1,
  keyLength: 32
};
```

**Impact:** With N=16384, a modern GPU can test millions of passwords per second. Combined with C1 (readable private key), an 8-character password can be cracked in hours.

**OWASP Recommendation:** N >= 2^17 for interactive, 2^20 for sensitive secrets.

**Fix:** Increase N to at least 2^17 (131072) for new vaults.

---

#### H3: Secrets Output to Stdout Without Warning

**File:** `commands/get.js:237-238`
**Code:**
```javascript
} else {
  process.stdout.write(content);  // Plaintext secrets!
}
```

**Issues:**
1. Secrets visible in terminal scrollback
2. May be logged by terminal emulator
3. May be captured by screen recording
4. No confirmation prompt for `-p` flag

**Fix:** Add confirmation prompt, warn about exposure.

---

#### H4: No Atomic Writes

**File:** `lib/vault.js` (all write operations)

**Impact:** If process crashes during write, vault files may be corrupted or partially written, potentially causing data loss.

**Fix:** Write to temp file, fsync, rename atomically.

---

### MEDIUM SEVERITY

#### M1: No File Locking for Concurrent Access

**Impact:** Two concurrent env-vault processes could corrupt vault files.

---

#### M2: Merge Preview Exposes Secret Values

**File:** `commands/get.js:172-180`
```javascript
console.log(`  ${key}: ${change.old} -> ${change.new}`);  // Prints secrets!
```

---

#### M3: No Package Lock File

**File:** Missing `package-lock.json`
**Impact:** Dependency versions not pinned, enabling supply-chain attacks.

---

#### M4: No Signed Releases or Checksums

**Impact:** Users cannot verify package authenticity.

---

#### M5: Editor Command Injection Risk

**File:** `commands/edit.js:55, 61`
```javascript
const editor = process.env.EDITOR || process.env.VISUAL || 'vi';
const child = spawn(editor, [tempFile], { stdio: 'inherit' });
```

**Impact:** If attacker controls EDITOR env var, arbitrary code execution. Mitigated by: attacker would need shell access anyway.

---

### LOW SEVERITY

#### L1: Public Key in Shell History

**Command:** `env-vault share <repo> <pubkey>`
**Impact:** Public key visible in `.bash_history`. Not secret, but exposes identity.

---

#### L2: No Zeroization of Secrets in Memory

**Impact:** JavaScript doesn't support secure memory; secrets may persist in heap.
**Mitigation:** Document as known limitation.

---

#### L3: 8-Character Password Minimum Too Low

**File:** `commands/init.js:38-40`
**Impact:** 8-char passwords are weak against offline attacks.
**Recommendation:** 12+ characters or passphrase.

---

## Phase 3: Team Sharability Assessment

### What's Safe

| Aspect | Status | Notes |
|--------|--------|-------|
| Cryptographic design | ✅ Safe | X25519 + AES-256-GCM is industry standard |
| Per-device keys | ✅ Safe | Compromise of one device doesn't expose others |
| Zero-knowledge | ✅ Safe | Private keys never leave device |
| Git workflow | ✅ Safe | Only encrypted data committed |
| Revocation model | ✅ Safe | Re-encrypt with new DEK after revoke |

### What's Unsafe (Until Fixed)

| Aspect | Status | Risk |
|--------|--------|------|
| File permissions | ❌ Unsafe | Local users can read encrypted keys |
| Temp file handling | ❌ Unsafe | Edit command exposes plaintext |
| KDF strength | ⚠️ Weak | Offline attacks feasible |
| stdout output | ⚠️ Risky | Secrets may leak to logs |
| No signed releases | ⚠️ Risky | Supply chain vulnerability |
| No tests | ⚠️ Risky | Regressions undetected |

### Team Readiness Checklist

**Before sharing with team:**

- [ ] Apply permission fixes (this audit)
- [ ] Increase KDF parameters (this audit)
- [ ] Fix temp file handling (this audit)
- [ ] Add package-lock.json
- [ ] Add security tests
- [ ] Document threat model in SECURITY.md
- [ ] Create team onboarding guide (TEAM.md)

**Team policies to establish:**

- [ ] Master password requirements (16+ chars or passphrase)
- [ ] Password manager usage (1Password/Bitwarden)
- [ ] Revocation process when teammate leaves
- [ ] Key rotation schedule
- [ ] CI/CD secret injection (avoid env-vault in CI)

---

## Summary of Required Fixes

| Priority | Fix | Effort |
|----------|-----|--------|
| Critical | File permissions 0600/0700 | Low |
| Critical | Directory permissions 0700 | Low |
| High | Secure temp file handling | Medium |
| High | Increase KDF N to 2^17 | Low |
| High | Add atomic writes | Medium |
| Medium | Add stdout warning | Low |
| Medium | Add package-lock.json | Low |
| Medium | Add security tests | Medium |
| Low | Add `env-vault doctor` command | Medium |

---

*End of Security Audit Report*
