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

## 🔒 Comprehensive Security Hardening

### Vulnerability Assessment & Mitigation (2025-10-05)

The OPNsense MCP Server underwent comprehensive security review and hardening, addressing multiple security domains:

#### **1. Dependency Vulnerabilities (12 Updates)**

**Critical/High Severity CVEs Fixed:**

| Package | Old Version | New Version | CVE | CVSS | Impact |
|---------|------------|-------------|-----|------|--------|
| httpx/h11 | ≥0.24.0 | ≥0.28.1 | CVE-2025-43859 | 9.1 (Critical) | Remote Code Execution via malformed HTTP responses |
| mcp | ≥0.1.0 | ≥1.9.4 | CVE-2025-53366 | 7.5 (High) | Denial of Service via unvalidated input |
| pydantic | ≥2.0.0 | ≥2.11.0 | CVE-2024-3772 | 6.5 (Medium) | ReDoS via crafted email validation |
| black | ≥23.0.0 | ≥25.9.0 | CVE-2024-21503 | 6.5 (Medium) | ReDoS via AST expression strings |
| ruff | ≥0.1.0 | ≥0.11.5 | CVE-2025-4574 | 5.3 (Medium) | Rust dependency vulnerabilities |

**Additional Stability Updates:**
- keyring: 24.0.0 → 25.6.0 (latest stable)
- aiolimiter: 1.1.0 → 1.2.1 (latest stable)
- typer: Added 0.19.0 (CLI consistency)
- certifi: Added 2024.0.0 (SSL/TLS hardening)

**Security Impact:** Mitigates Remote Code Execution, Denial of Service, and Regular Expression Denial of Service attacks.

---

#### **2. Error Message Sanitization**

**New Module:** `src/opnsense_mcp/shared/error_sanitizer.py`

**Purpose:** Prevent information disclosure through error messages sent to LLM or users.

**Key Features:**
```python
class ErrorMessageSanitizer:
    """Sanitize error messages for safe user display."""

    # Detects and redacts sensitive patterns
    SENSITIVE_PATTERNS = [
        "password", "api_key", "api_secret", "token",
        "credential", "authorization", "bearer", "secret"
    ]

    @staticmethod
    def sanitize_for_user(error: Exception) -> str:
        """Return user-safe error message without sensitive details."""
        # Returns generic messages like:
        # "Authentication failed. Please check your OPNsense credentials."

    @staticmethod
    def sanitize_for_logs(error: Exception) -> Dict[str, Any]:
        """Return detailed error info for logging (never shown to users)."""
        # Includes full context for debugging, stored locally only
```

**Security Impact:** Prevents credential leakage in error messages while maintaining debugging capabilities.

---

#### **3. Dangerous Endpoint Protection**

**Modified:** `src/opnsense_mcp/shared/constants.py`, `src/opnsense_mcp/domains/utilities.py`

**Classification:** 33 high-risk endpoints across 3 risk levels:

**CRITICAL (6 endpoints) - Blocked completely:**
- `/core/firmware/reinstall` - System reinstall
- `/core/firmware/poweroff` - System shutdown
- `/core/firmware/reboot` - System reboot
- `/core/backup/restore` - Full config restore
- `/system/reset` - System reset
- `/system/factory` - Factory reset

**HIGH (17 endpoints) - Blocked for write operations:**
- `/firewall/filter/delRule` - Delete firewall rules
- `/firewall/alias/delItem` - Delete firewall aliases
- `/nat/portforward/delRule` - Delete NAT rules
- `/interfaces/vlan/delItem` - Delete VLANs
- `/dhcpd/leases/wipe` - Wipe DHCP leases
- 12 additional destructive operations

**MEDIUM (9 endpoints) - Blocked for POST/PUT/DELETE:**
- `/firewall/filter/apply` - Apply firewall changes
- `/core/service/restart` - Restart services
- 7 additional operations requiring careful review

**Validation Function:**
```python
def validate_endpoint_safety(endpoint: str, method: str) -> None:
    """
    Validate API endpoint for safety before execution.

    Prevents accidental execution of dangerous endpoints that could cause:
    - System reboots/poweroff
    - Factory resets
    - Bulk deletions
    - Irreversible configuration changes
    """
    # Checks endpoint against risk classification
    # Blocks CRITICAL operations completely
    # Blocks HIGH/MEDIUM operations for write methods
```

**Security Impact:** Prevents destructive operations via LLM hallucinations or misinterpreted user prompts.

---

#### **4. Port Validation Enhancement**

**Modified:** `src/opnsense_mcp/domains/firewall.py`

**New Function:** `validate_port_specification()`

**Validation Rules:**
- Port numbers must be within valid range (1-65535)
- Port ranges must have start < end
- Supports single ports (80), ranges (80-443), and lists (80,443,8080)

**Examples:**
```python
validate_port_specification("80", "firewall_add_rule")          # ✅ Valid
validate_port_specification("80-443", "firewall_add_rule")      # ✅ Valid
validate_port_specification("80,443,8080", "firewall_add_rule") # ✅ Valid
validate_port_specification("70000", "firewall_add_rule")       # ❌ Invalid - out of range
validate_port_specification("443-80", "firewall_add_rule")      # ❌ Invalid - end < start
validate_port_specification("abc", "firewall_add_rule")         # ❌ Invalid - non-numeric
```

**Security Impact:** Prevents invalid port specifications that could create firewall rule misconfigurations.

---

#### **5. SSL/TLS Hardening**

**Modified:** `src/opnsense_mcp/core/client.py`

**New Method:** `_create_ssl_context()`

**Security Features:**
```python
def _create_ssl_context(self, verify_ssl: bool) -> ssl.SSLContext:
    """
    Create SSL context with security hardening.

    Production Configuration:
    - Enforces TLS 1.2+ minimum version
    - Uses certifi for up-to-date CA certificates
    - Enables certificate validation
    - Enables hostname verification
    """
    if not verify_ssl:
        logger.warning(
            "🔓 SSL CERTIFICATE VERIFICATION IS DISABLED! 🔓\n"
            "Connection is vulnerable to Man-in-the-Middle (MITM) attacks.\n"
            "This should ONLY be used in isolated lab environments.\n"
            "NEVER disable SSL verification in production."
        )
        # ... creates insecure context with warning

    # Production SSL context
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Disable SSLv3, TLS 1.0, TLS 1.1

    return context
```

**Security Impact:** Prevents protocol downgrade attacks, ensures up-to-date CA certificates, provides clear warnings for insecure configurations.

---

#### **6. Credential Rotation Detection**

**Modified:** `src/opnsense_mcp/core/state.py`, `src/opnsense_mcp/domains/configuration.py`

**New Feature:** Automatic credential rotation detection and reinitialization

**Implementation:**
```python
@dataclass
class ServerState:
    _current_profile: Optional[str] = None  # Track which profile is loaded

    def _config_changed(self, new_config: OPNsenseConfig, old_config: OPNsenseConfig) -> bool:
        """Detect if credentials have changed between configs."""
        return (
            new_config.url != old_config.url or
            new_config.api_key != old_config.api_key or
            new_config.api_secret != old_config.api_secret
        )

    async def get_client(self) -> 'OPNsenseClient':
        """Get client with credential rotation detection."""
        # Check for credential rotation (if profile is tracked)
        if self._current_profile:
            current_config = ConfigLoader.load(self._current_profile)

            if self._config_changed(current_config, self.config):
                logger.info("Credentials changed, reinitializing...")
                await self.initialize(current_config)

        return await self.pool.get_client(self.config)
```

**Security Impact:** Automatically detects when credentials are rotated in config files and reinitializes connections, preventing stale credential usage.

---

#### **7. Password Security Warnings**

**Modified:** `src/opnsense_mcp/domains/users.py`

**Enhanced Tools:** `create_user()`, `update_user()`

**New Documentation:**
```python
"""Create a new user account in OPNsense.

**SECURITY WARNING:** Passwords are transmitted in plaintext to OPNsense and hashed server-side.
Always use strong, unique passwords (minimum 12+ characters with mixed case, numbers, symbols).
Never reuse passwords across accounts or services.

Args:
    password: Password for the user (will be hashed server-side)
              WARNING: Use strong passwords (12+ chars, mixed case, numbers, symbols)
"""
```

**Security Impact:** Educates users about password security and transmission, encouraging strong password practices.

---

### Attack Vectors Mitigated

| Attack Vector | Mitigation | Status |
|---------------|------------|--------|
| Remote Code Execution | httpx/h11 update (CVE-2025-43859) | ✅ Fixed |
| Denial of Service | MCP SDK update (CVE-2025-53366) | ✅ Fixed |
| ReDoS Attacks | Pydantic/Black updates | ✅ Fixed |
| Information Disclosure | Error message sanitization | ✅ Fixed |
| MITM Attacks | SSL/TLS 1.2+ enforcement | ✅ Fixed |
| Protocol Downgrade | TLS version restrictions | ✅ Fixed |
| Destructive Operations | Endpoint risk classification | ✅ Fixed |
| Port Misconfigurations | Comprehensive port validation | ✅ Fixed |
| Stale Credentials | Automatic rotation detection | ✅ Fixed |
| Weak Passwords | Security warnings & education | ✅ Fixed |

---

### Security Testing

Run comprehensive security tests:

```bash
# Full security test suite
pytest tests/test_security/ -v

# Credential security tests
pytest tests/test_security/test_credential_security.py -v

# Error sanitization tests
pytest tests/test_security/test_error_sanitizer.py -v

# Endpoint safety tests
pytest tests/test_domains/test_utilities.py::TestEndpointValidation -v
```

---

### Security Maintenance

**Recommended Actions:**

1. **Regular Dependency Updates**
   ```bash
   # Check for security updates quarterly
   pip list --outdated
   pip-audit  # If installed
   ```

2. **Monitor CVE Databases**
   - [GitHub Security Advisories](https://github.com/advisories)
   - [Python CVE Database](https://www.cvedetails.com/vulnerability-list/vendor_id-10210/product_id-18230/)
   - [NIST NVD](https://nvd.nist.gov/)

3. **Review Access Logs**
   ```bash
   # Check OPNsense API access logs
   opnsense-mcp exec_api_call GET "/api/diagnostics/log/core/system"
   ```

4. **Audit Configurations**
   ```bash
   # Test connections regularly
   opnsense-mcp test-connection --profile production

   # Verify permissions
   ls -l ~/.opnsense-mcp/config.json  # Should show -rw-------
   ```

---

## 📚 Additional Resources

- [MCP Security Best Practices](https://docs.anthropic.com/en/docs/agents-and-tools/mcp)
- [OPNsense API Documentation](https://docs.opnsense.org/development/api.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

---

**Remember:** Security is a shared responsibility. Keep your local machine secure, use strong passwords, enable encryption, and follow best practices for credential management. This server implements defense-in-depth security controls to protect your firewall infrastructure.
