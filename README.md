# env-vault

Secure environment variable management with encryption and sharing capabilities.

## Prerequisites

- **Node.js 18+**
- **C++ build tools** (required for argon2 encryption):
  - **macOS**: `xcode-select --install`
  - **Ubuntu/Debian**: `sudo apt install build-essential python3`
  - **Windows**: `npm install -g windows-build-tools` (run as Administrator)

## Installation

```bash
npm install -g env-vault
```

## Quick Start

```bash
# 1. Initialize your vault with a master password
env-vault init

# 2. Initialize env-vault in a project directory
cd your-project
env-vault init-repo .env

# 3. Get decrypted secrets
env-vault get

# 4. Share with a teammate (they need to run env-vault init first)
env-vault share . <their-public-key>
```

## Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new vault with a master password |
| `identity` | Show your public key (share this to receive secrets) |
| `init-repo [envFile]` | Initialize .env-vault in current project directory |
| `get [repo] [file]` | Get decrypted secrets for a repository |
| `add <repo> [file]` | Add or update secrets for a repository |
| `list` | List all repositories |
| `rm <repo>` | Remove a repository |
| `edit <repo>` | Edit secrets in your default editor |

### Sharing Commands

| Command | Description |
|---------|-------------|
| `share <repo> <pubkey>` | Share a repository with a public key |
| `revoke <repo> <fingerprint>` | Revoke access to a repository |
| `recipients <repo>` | List recipients who have access |

### Git Sync Commands

| Command | Description |
|---------|-------------|
| `sync` | Sync vault with remote git repository |
| `clone <git-url>` | Clone an existing vault from git |
| `migrate` | Migrate repos from central vault to per-project storage |

## How It Works

env-vault uses public-key cryptography to securely store and share environment variables:

1. **Initialization**: Creates a unique X25519 keypair for your device
2. **Encryption**: Secrets are encrypted with AES-256-GCM using a random data encryption key (DEK)
3. **Key Wrapping**: The DEK is wrapped (encrypted) for each recipient's public key
4. **Sharing**: To share, you wrap the DEK for the recipient's public key
5. **Storage**: Encrypted secrets can be committed to git safely

```
┌─────────────────────────────────────────────────────────┐
│                    .env-vault/                          │
├─────────────────────────────────────────────────────────┤
│  secrets.enc      - AES-256-GCM encrypted secrets       │
│  recipients.json  - Wrapped DEKs for each recipient     │
└─────────────────────────────────────────────────────────┘
```

## Workflow Example

### Team Setup

```bash
# Alice (project owner)
env-vault init                    # Create identity
env-vault init-repo .env          # Encrypt project secrets
git add .env-vault/ && git commit -m "Add encrypted secrets"
git push

# Bob (teammate)
env-vault init                    # Create his own identity
env-vault identity                # Shows his public key
# Send public key to Alice

# Alice shares with Bob
env-vault share . <bob-public-key>
git add .env-vault/ && git commit -m "Share with Bob"
git push

# Bob can now decrypt
git pull
env-vault get                     # Outputs decrypted secrets
env-vault get .env                # Writes to .env file
```

## Security

- **End-to-end encryption**: Secrets are encrypted locally before storage
- **Zero-knowledge**: Private keys never leave your device
- **Proven cryptography**: X25519 + AES-256-GCM + Argon2id
- **No plaintext in git**: Only encrypted data is committed
- **Per-device keys**: Each device has its own keypair

## File Locations

| Path | Description |
|------|-------------|
| `~/.env-vault/` | Central vault directory |
| `~/.env-vault/identity/` | Your keypair (private.key is encrypted) |
| `~/.env-vault/repos/` | Central repository storage |
| `./.env-vault/` | Per-project encrypted secrets |

## Troubleshooting

### "Failed to unlock vault. Wrong password?"
- Check that you're entering the correct master password
- The password is case-sensitive

### "Vault not initialized"
- Run `env-vault init` to create your identity first

### Installation fails with node-gyp errors
- Ensure you have C++ build tools installed (see Prerequisites)
- Try: `npm install -g env-vault --build-from-source`

## License

MIT
