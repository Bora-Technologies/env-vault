# Security Policy

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Email: security@bora-technologies.com
Subject: "env-vault Security Vulnerability"

We will acknowledge within 48 hours and provide a fix timeline.

---

## Security Architecture

### Cryptographic Design

env-vault uses industry-standard cryptography:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Symmetric encryption | AES-256-GCM | Encrypt secrets with DEK |
| Key derivation | scrypt (N=2^17, r=8, p=1) | Derive key from master password |
| Asymmetric encryption | X25519 + XSalsa20-Poly1305 | Wrap DEK for recipients |
| Hashing | SHA-256 | Generate fingerprints |

### Key Hierarchy

```
Master Password (user memory)
        │
        ▼ scrypt (N=131072, r=8, p=1)
   Derived Key
        │
        ▼ AES-256-GCM
   Encrypted Private Key (stored)
        │
        ▼ (decrypt on unlock)
   Private Key (memory only)
        │
        ▼ X25519 openBox
       DEK
        │
        ▼ AES-256-GCM
   Plaintext Secrets
```

### Security Properties

- **End-to-end encryption**: Secrets are encrypted before leaving your device
- **Zero-knowledge**: Private keys never leave the device; only wrapped DEKs are shared
- **Authenticated encryption**: AES-GCM provides both confidentiality and integrity
- **Forward secrecy**: Each DEK wrap uses a fresh ephemeral keypair
- **Per-device isolation**: Each device has its own keypair

---

## Threat Model

### Assets Protected

| Asset | Sensitivity | Storage |
|-------|-------------|---------|
| Master password | Critical | User memory |
| Private key (decrypted) | Critical | Memory only |
| DEK | Critical | Memory only |
| Plaintext secrets | Critical | Memory, output files |
| Private key (encrypted) | High | ~/.env-vault/identity/private.key |
| Encrypted secrets | Medium | .env-vault/secrets.enc |

### Trust Boundaries

1. **User device** - Trusted execution environment
2. **Filesystem** - Protected by OS permissions
3. **Git repository** - Only encrypted data committed
4. **Network** - All transmitted data is encrypted

### Threat Actors

| Actor | Capability | Mitigations |
|-------|------------|-------------|
| Laptop thief | Disk access | Encrypted private key, strong KDF |
| Malicious local user | Read files | 0600/0700 permissions |
| Supply chain attacker | Modify package | package-lock.json, audit |
| Insider (revoked) | Previous access | Re-encrypt with new DEK on revoke |
| Network observer | Intercept traffic | All data encrypted at rest |

---

## Security Guarantees

### What We Protect

- Secrets are never stored in plaintext (except when exported)
- Private keys are encrypted at rest with a password-derived key
- DEKs are never transmitted in plaintext
- Each recipient has a uniquely wrapped DEK

### What We Don't Protect

- **Clipboard content** - If you copy secrets, they're in system clipboard
- **Process memory** - Secrets exist in memory during operations
- **Shell history** - `-p` output may be captured in scrollback
- **Weak passwords** - 8-char minimum; we recommend 16+ or passphrase
- **Compromised device** - If attacker has root, all bets are off

### Known Limitations

1. **JavaScript memory** - No secure zeroization (language limitation)
2. **Terminal output** - `-p` flag prints secrets to stdout
3. **Temp files during edit** - Mitigated with secure random paths and cleanup
4. **No hardware security** - No HSM/TPM integration yet

---

## File Permissions

All sensitive files are created with restrictive permissions:

| Path | Mode | Description |
|------|------|-------------|
| `~/.env-vault/` | 0700 | Vault root directory |
| `~/.env-vault/identity/` | 0700 | Identity directory |
| `~/.env-vault/identity/private.key` | 0600 | Encrypted private key |
| `~/.env-vault/identity/salt` | 0600 | KDF salt |
| `.env-vault/` | 0700 | Per-project vault |
| `.env-vault/secrets.enc` | 0600 | Encrypted secrets |

### Verifying Permissions

```bash
env-vault doctor          # Check current permissions
env-vault doctor --fix    # Fix insecure permissions
```

---

## Security Best Practices

### Password Requirements

- **Minimum**: 8 characters (enforced)
- **Recommended**: 16+ characters or passphrase
- **Store in**: 1Password, Bitwarden, or similar

### Safe Usage

```bash
# Good: Output to file (not visible in terminal)
env-vault get

# Risky: Output to stdout (visible in scrollback)
env-vault get -p

# Safe: Pipe to command (no terminal exposure)
env-vault get -p | grep API_KEY | pbcopy
```

### Git Safety

Always ensure `.env*` is in `.gitignore`:

```gitignore
# .gitignore
.env
.env.*
!.env.example
```

### CI/CD Security

- **Don't** use env-vault in CI pipelines (secrets would need to be injected)
- **Do** use your CI platform's native secrets management
- **Do** commit `.env-vault/` to git (it's encrypted)

---

## Security Updates

### Version 0.0.15

- Hardened scrypt parameters (N=2^14 -> N=2^17)
- Added file permission enforcement (0600/0700)
- Atomic file writes to prevent corruption
- Secure temp file handling in edit command
- Added `env-vault doctor` command

### Upgrade Path

Existing vaults created with older versions will continue to work. The unlock process automatically detects and uses legacy parameters when needed, with a warning to upgrade.

---

## Cryptographic Details

### AES-256-GCM

- **IV**: 12 bytes, randomly generated per encryption
- **Auth tag**: 16 bytes
- **Format**: `IV (12) || Ciphertext || AuthTag (16)`

### X25519 Sealed Box

- **Ephemeral keypair**: Generated per wrap operation
- **Nonce**: 24 bytes, randomly generated
- **Format**: `EphemeralPubKey (32) || Nonce (24) || Ciphertext`

### Scrypt Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| N | 131072 (2^17) | CPU/memory cost |
| r | 8 | Block size |
| p | 1 | Parallelization |
| keyLength | 32 | Output key size |
| maxmem | 256 MB | Memory allocation |

---

## Audit & Testing

Security tests are included:

```bash
npm test
```

Tests cover:
- Encrypt/decrypt roundtrip
- Tamper detection
- Wrong key rejection
- IV uniqueness
- Permission enforcement
- Path traversal prevention

---

## Contact

- Security issues: security@bora-technologies.com
- General issues: https://github.com/Bora-Technologies/env-vault/issues
