# 🔒 Security - OPNsense MCP Server

## Overview

The OPNsense MCP Server implements **secure local-only credential storage** to ensure your firewall credentials never leave your machine and are never exposed to AI models or external services.

## 🎯 Security Architecture

### Local-Only Credential Storage

**KEY PRINCIPLE:** Credentials are stored locally and referenced by profile name only when communicating with AI models.

```
❌ BEFORE (Insecure):
User → Claude → "configure_opnsense_connection(url, api_key, api_secret)" → Credentials exposed to LLM

✅ AFTER (Secure):
User → Claude → "configure_opnsense_connection(profile='default')" → Profile name only
         ↓
    Local Machine reads credentials from ~/.opnsense-mcp/config.json
         ↓
    Credentials never sent to LLM
```

## 🔐 Credential Storage Methods

The OPNsense MCP Server supports three credential storage methods with cascading priority:

### 1. Environment Variables (Highest Priority) ⭐ Recommended for CI/CD

```bash
export OPNSENSE_URL="https://192.168.1.1"
export OPNSENSE_API_KEY="your-api-key"
export OPNSENSE_API_SECRET="your-api-secret"
export OPNSENSE_VERIFY_SSL="true"  # or "false"
```

**Use Cases:**
- CI/CD pipelines
- Docker containers
- Automated deployments
- Temporary testing

**Security:**
- ✅ No files to secure
- ✅ Process-local only
- ⚠️ Visible in process environment
- ⚠️ May appear in shell history (use `.env` files)

### 2. Config File (Recommended for Local Development) ⭐ Recommended for Desktop

```bash
# Setup using interactive CLI
opnsense-mcp setup

# Or setup specific profile
opnsense-mcp setup --profile production
```

**File Location:** `~/.opnsense-mcp/config.json`

**Security Features:**
- ✅ Automatic `0600` permissions (owner read/write only)
- ✅ Multiple profile support
- ✅ Easy to backup/restore
- ✅ Human-readable JSON format

**Config File Format:**
```json
{
  "default": {
    "url": "https://192.168.1.1",
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
    "verify_ssl": true
  },
  "production": {
    "url": "https://firewall.example.com",
    "api_key": "prod-api-key",
    "api_secret": "prod-api-secret",
    "verify_ssl": true
  }
}
```

### 3. System Keyring (Backward Compatibility)

Legacy method maintained for backward compatibility. New installations should use config file or environment variables.

## 🛡️ Security Best Practices

### File Permissions

The server automatically sets secure permissions on config files:

```bash
# Verify config file permissions
ls -la ~/.opnsense-mcp/config.json
# Should show: -rw------- (0600) - owner read/write only
```

If permissions are incorrect, the server will attempt to fix them automatically and warn you.

### Profile Management

```bash
# List all configured profiles
opnsense-mcp list-profiles

# Show profile details (credentials NOT shown)
opnsense-mcp list-profiles --verbose

# Test connection without exposing credentials
opnsense-mcp test-connection --profile production

# Delete unused profiles
opnsense-mcp delete-profile staging
```

### Multi-Environment Setup

For managing multiple firewalls securely:

```bash
# Development firewall
opnsense-mcp setup --profile dev

# Staging firewall
opnsense-mcp setup --profile staging

# Production firewall
opnsense-mcp setup --profile production
```

Then in Claude Desktop:
- *"Configure OPNsense using dev profile"*
- *"Switch to production OPNsense"*
- *"Connect to staging firewall"*

## 🚨 Security Considerations

### What is Protected ✅

1. **Credentials Never Sent to LLM**
   - API keys and secrets stay on your machine
   - Only profile names are transmitted
   - MCP tool signature changed to prevent credential parameters

2. **Secure File Storage**
   - Config files have `0600` permissions (owner only)
   - Automatic permission enforcement
   - Protected in `.gitignore` to prevent accidental commits

3. **No Credential Logging**
   - API secrets marked `repr=False` in Pydantic models
   - Comprehensive logging filters
   - Test suite verifies no credential leakage

4. **Profile Info Safety**
   - API keys shown as preview only (first 4 + last 4 chars)
   - Secrets never exposed in any output
   - Error messages provide guidance without credentials

### What to Be Aware Of ⚠️

1. **Local Machine Security**
   - Credentials are as secure as your local machine
   - Use full-disk encryption
   - Lock your screen when away
   - Use strong user passwords

2. **Config File Backup**
   - If backing up config files, use encrypted backups
   - Never commit config files to version control
   - Be careful with cloud sync (Dropbox, iCloud, etc.)

3. **Environment Variables**
   - May appear in shell history
   - Use `.env` files with proper permissions
   - Clear shell history if needed: `history -c`

4. **Sharing Profiles**
   - Don't share config files via insecure channels
   - Use encrypted channels (SSH, encrypted email)
   - Consider using unique API keys per user

## 🔧 Migrating from Old Credential Method

If you were using the old method where credentials were passed directly:

### Before (Insecure)
```
User: "Configure OPNsense at 192.168.1.1 with key ABC123 and secret XYZ789"
```

### After (Secure)
```bash
# One-time setup (local machine)
opnsense-mcp setup
# Enter your credentials interactively (secure password input)

# Then in Claude Desktop
User: "Configure OPNsense connection"
# Credentials loaded from local storage automatically
```

## 📋 Security Checklist

Before production use, verify:

- [ ] Config file exists: `~/.opnsense-mcp/config.json`
- [ ] Config file has correct permissions: `ls -l ~/.opnsense-mcp/config.json` shows `-rw-------`
- [ ] Test connection works: `opnsense-mcp test-connection`
- [ ] Config file excluded from version control (check `.gitignore`)
- [ ] Credentials not in shell history: `history | grep OPNSENSE`
- [ ] Full-disk encryption enabled on local machine
- [ ] Regular backups of config file (encrypted)

## 🆘 Security Incident Response

### If Credentials are Compromised

1. **Immediately revoke API keys in OPNsense**
   - System → Access → Users → Edit API User
   - Click "Revoke" on compromised API key

2. **Generate new API credentials**
   - System → Access → Users → Edit API User
   - Click "+" to generate new key/secret

3. **Update local config**
   ```bash
   opnsense-mcp setup --profile default
   # Enter new credentials
   ```

4. **Review access logs**
   - System → Log Files → Web GUI
   - Look for unauthorized API access

### If Config File is Accidentally Committed to Git

1. **Immediately remove from repository**
   ```bash
   git rm --cached ~/.opnsense-mcp/config.json
   git commit -m "Remove accidentally committed credentials"
   git push --force
   ```

2. **Consider repository compromised**
   - Revoke all API keys in config file
   - Generate new credentials
   - Update local config

3. **Rewrite Git history if needed** (use with caution)
   ```bash
   git filter-branch --force --index-filter \
     'git rm --cached --ignore-unmatch config.json' \
     --prune-empty --tag-name-filter cat -- --all
   ```

## 📞 Security Contact

For security vulnerabilities or concerns, please:

1. **Do NOT open a public GitHub issue**
2. **Use GitHub Security Advisories** to report vulnerabilities privately:
   - Go to the [Security tab](https://github.com/floriangrousset/opnsense-mcp-server/security)
   - Click "Report a vulnerability"
   - Include:
     - Description of vulnerability
     - Steps to reproduce
     - Potential impact
     - Suggested fix (if any)

Security reports are reviewed by project maintainers.

## 🔍 Security Testing

The project includes comprehensive security tests:

```bash
# Run security test suite
pytest tests/test_security/

# Run integration tests including security scenarios
pytest tests/test_integration/test_secure_config.py

# Verify no credential leakage
pytest tests/test_security/test_credential_security.py -v
```

All tests verify that:
- Credentials never appear in tool responses
- Credentials never appear in error messages
- Credentials never appear in log output
- Config files have secure permissions
- Tool signatures don't accept credential parameters

## 📚 Additional Resources

- [MCP Security Best Practices](https://docs.anthropic.com/en/docs/agents-and-tools/mcp)
- [OPNsense API Documentation](https://docs.opnsense.org/development/api.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

**Remember:** Security is a shared responsibility. Keep your local machine secure, use strong passwords, enable encryption, and follow best practices for credential management.
