# Team Guide for env-vault

This guide covers how to safely use env-vault in a team environment.

---

## Quick Setup for New Team Members

### 1. Install env-vault

```bash
npm install -g @bora-technologies/env-vault
```

### 2. Initialize Your Identity

```bash
env-vault init
```

You'll be prompted to:
- Enter a device label (e.g., "MacBook Pro")
- Create a master password (16+ characters recommended)

**Important**: Store your master password in a password manager (1Password, Bitwarden, etc.). There is no recovery if you forget it.

### 3. Share Your Public Key

```bash
env-vault identity
```

This displays your public key. Send it to a teammate who has access to the project secrets.

### 4. Get Access (After Teammate Shares)

Once a teammate runs `env-vault share` with your public key:

```bash
git pull                  # Get the updated .env-vault/recipients.json
env-vault get             # Decrypt secrets to .env
```

---

## Recommended Workflow

### Project Owner Setup

```bash
# 1. Initialize vault (if not already done)
env-vault init

# 2. In your project directory with a .env file
cd my-project
env-vault init-repo .env

# 3. Commit encrypted secrets
git add .env-vault/
git commit -m "Add encrypted secrets"
git push
```

### Sharing with Team

```bash
# Teammate sends their public key (from `env-vault identity`)
# Owner runs:
env-vault share . <teammate-public-key> --label "Alice's laptop"

# Commit and push
git add .env-vault/recipients.json
git commit -m "Share secrets with Alice"
git push
```

### Updating Secrets

```bash
# Option 1: Update from .env file
env-vault add .

# Option 2: Edit in-place
env-vault edit my-repo
```

---

## Do's and Don'ts

### Do

- Store your master password in a password manager
- Use a strong passphrase (16+ characters)
- Run `env-vault doctor` periodically
- Commit `.env-vault/` to your repository
- Add `.env*` to `.gitignore`
- Re-key secrets when a teammate leaves

### Don't

- Store your master password in plain text
- Share your master password with anyone
- Commit plaintext `.env` files to git
- Use `-p` flag in shared terminals or logs
- Store secrets in CI/CD variables that came from env-vault (defeats the purpose)

---

## Revoking Access

When a teammate leaves or loses their device:

```bash
# Remove their access
env-vault revoke . <fingerprint>

# Secrets are automatically re-encrypted with a new DEK
# All other recipients automatically re-wrapped

# Commit
git add .env-vault/
git commit -m "Revoke access for departed teammate"
git push
```

---

## Multi-Device Setup

Each device needs its own identity:

```bash
# On new device
env-vault init --label "Work Desktop"
env-vault identity   # Get the new public key

# Existing device shares with new device
env-vault share . <new-device-pubkey> --label "My Work Desktop"

# On new device
git pull
env-vault get
```

---

## Troubleshooting

### "You don't have access"

Someone needs to share the repo with your public key:
```bash
env-vault identity  # Show your public key
# Send to teammate, they run: env-vault share . <your-pubkey>
git pull
env-vault get
```

### "Failed to unlock vault. Wrong password?"

- Double-check your master password (case-sensitive)
- If you forgot your password: `env-vault reset` (you'll need someone to re-share)

### "Vault not initialized"

Run `env-vault init` first to create your identity.

### Permission issues

```bash
env-vault doctor --fix
```

---

## Security Checklist for Teams

Before rolling out to your team:

- [ ] All team members use password managers
- [ ] Master password policy: 16+ characters or passphrase
- [ ] `.gitignore` includes `.env*`
- [ ] Revocation process documented
- [ ] Periodic access audit scheduled
- [ ] Backup process for owners (don't lose the only copy)

---

## CI/CD Considerations

env-vault is designed for **local development**, not CI/CD:

- **CI/CD pipelines** should use native secrets management (GitHub Secrets, AWS Secrets Manager, etc.)
- **Do commit** `.env-vault/` so developers can decrypt locally
- **Don't** inject env-vault's master password into CI

### Migration from CI secrets to env-vault

If you currently store secrets in CI:
1. Continue using CI secrets for pipelines
2. Use env-vault for local development only
3. Keep both in sync manually or via tooling

---

## Emergency Procedures

### Lost Master Password

```bash
env-vault reset     # Deletes your identity
env-vault init      # Create new identity
# Ask teammate to re-share access
```

### Stolen Laptop

1. Revoke the device's access immediately
2. Rotate any secrets that might be compromised
3. Update all repos with new DEK

### Suspected Breach

1. Revoke all access: `env-vault revoke . <fingerprint>` for each recipient
2. Rotate all secrets in the source systems
3. Re-add only verified team members
4. Consider rotating the DEK manually

---

## FAQ

**Q: Can I share the same identity across devices?**
A: No, each device should have its own identity. This allows granular revocation.

**Q: What if I lose my laptop?**
A: Your encrypted private key requires your master password. Revoke that device's access as a precaution.

**Q: How do I rotate secrets?**
A: Update your `.env` file, then run `env-vault add .`. This re-encrypts with a new DEK.

**Q: Can I use this with Docker?**
A: Yes. Run `env-vault get` before building, or mount `.env` into the container.

**Q: Is the encrypted data safe to commit?**
A: Yes, `.env-vault/secrets.enc` is encrypted with AES-256-GCM. Only the ciphertext is stored.

---

## Contact

- Issues: https://github.com/Bora-Technologies/env-vault/issues
- Security: security@bora-technologies.com
