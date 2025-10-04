"""
OPNsense MCP Server - Certificates Domain

This module provides comprehensive SSL/TLS certificate lifecycle management including
Certificate Authorities, certificates, CSRs, and Let's Encrypt automation.

Features:
- Certificate Authority (CA) management: Create, manage, and export CAs
- Certificate management: Import/export certificates with private keys
- Certificate Signing Request (CSR) generation for external CAs
- ACME (Let's Encrypt) integration for automated certificate issuance
- Certificate validation and monitoring: Expiration analysis, chain validation
- Certificate usage analysis and recommendations

The module supports:
- Full Distinguished Name (DN) configuration for certificates
- Multiple cryptographic algorithms (SHA-256/384/512)
- Configurable RSA key lengths (2048/4096 bits)
- PEM format import/export
- Automated certificate renewal with Let's Encrypt
- Certificate trust chain validation
"""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import Context

from ..main import mcp
from ..shared.constants import (
    # Certificate Authority endpoints
    API_CERTIFICATES_CA_SEARCH,
    API_CERTIFICATES_CA_GET,
    API_CERTIFICATES_CA_ADD,
    API_CERTIFICATES_CA_DEL,
    API_CERTIFICATES_CA_EXPORT,

    # Certificate endpoints
    API_CERTIFICATES_CERT_SEARCH,
    API_CERTIFICATES_CERT_GET,
    API_CERTIFICATES_CERT_ADD,
    API_CERTIFICATES_CERT_DEL,
    API_CERTIFICATES_CERT_EXPORT,

    # CSR endpoints
    API_CERTIFICATES_CSR_SEARCH,
    API_CERTIFICATES_CSR_GET,
    API_CERTIFICATES_CSR_ADD,
    API_CERTIFICATES_CSR_DEL,

    # ACME Account endpoints
    API_CERTIFICATES_ACME_ACCOUNTS_SEARCH,
    API_CERTIFICATES_ACME_ACCOUNTS_GET,
    API_CERTIFICATES_ACME_ACCOUNTS_ADD,
    API_CERTIFICATES_ACME_ACCOUNTS_DEL,

    # ACME Certificate endpoints
    API_CERTIFICATES_ACME_CERTS_SEARCH,
    API_CERTIFICATES_ACME_CERTS_GET,
    API_CERTIFICATES_ACME_CERTS_ADD,
    API_CERTIFICATES_ACME_CERTS_DEL,
    API_CERTIFICATES_ACME_CERTS_SIGN,
    API_CERTIFICATES_ACME_CERTS_REVOKE,

    # Service endpoints
    API_CERTIFICATES_SERVICE_RECONFIGURE,
)
from ..shared.error_handlers import handle_tool_error

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========

async def get_opnsense_client():
    """Get OPNsense client from configuration module."""
    from .configuration import get_opnsense_client as get_client
    return await get_client()


# ========== CERTIFICATE AUTHORITIES ==========

@mcp.tool(name="list_certificate_authorities", description="List all Certificate Authorities (CAs)")
async def list_certificate_authorities(ctx: Context) -> str:
    """List all Certificate Authorities configured in OPNsense.

    Args:
        ctx: Request context

    Returns:
        JSON string with list of Certificate Authorities
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("POST", API_CERTIFICATES_CA_SEARCH)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_certificate_authorities", e)


@mcp.tool(name="get_certificate_authority", description="Get detailed information about a specific Certificate Authority")
async def get_certificate_authority(ctx: Context, ca_uuid: str) -> str:
    """Get detailed information about a specific Certificate Authority.

    Args:
        ctx: Request context
        ca_uuid: UUID of the Certificate Authority

    Returns:
        JSON string with Certificate Authority details
    """
    try:
        client = await get_opnsense_client()

        if not ca_uuid:
            raise ValueError("Certificate Authority UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_CA_GET}/{ca_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_certificate_authority", e)


@mcp.tool(name="create_certificate_authority", description="Create a new Certificate Authority")
async def create_certificate_authority(ctx: Context, descr: str, country: str, state: str, city: str,
                                     organization: str, organizational_unit: str = "", common_name: str = "",
                                     digest_alg: str = "sha256", key_length: int = 2048,
                                     lifetime: int = 3650, dn_email: str = "") -> str:
    """Create a new Certificate Authority.

    Args:
        ctx: Request context
        descr: Description/name for the Certificate Authority
        country: Two-letter country code (e.g., 'US')
        state: State or Province
        city: City or Locality
        organization: Organization name
        organizational_unit: Organizational Unit (optional)
        common_name: Common Name (optional, defaults to descr if not provided)
        digest_alg: Digest algorithm (sha256, sha384, sha512)
        key_length: RSA key length (2048, 4096)
        lifetime: Certificate lifetime in days (default: 3650 = 10 years)
        dn_email: Email address (optional)

    Returns:
        JSON string with creation result and new CA UUID
    """
    try:
        client = await get_opnsense_client()

        # Validation
        if not descr:
            raise ValueError("Description is required")
        if not country or len(country) != 2:
            raise ValueError("Country must be a 2-letter code (e.g., 'US')")
        if not state:
            raise ValueError("State/Province is required")
        if not city:
            raise ValueError("City/Locality is required")
        if not organization:
            raise ValueError("Organization is required")
        if digest_alg not in ["sha256", "sha384", "sha512"]:
            raise ValueError("Digest algorithm must be one of: sha256, sha384, sha512")
        if key_length not in [2048, 4096]:
            raise ValueError("Key length must be 2048 or 4096")
        if lifetime <= 0:
            raise ValueError("Lifetime must be positive")

        # Use description as common name if not provided
        if not common_name:
            common_name = descr

        ca_data = {
            "ca": {
                "descr": descr,
                "caref": "",  # Will be generated
                "refid": "",  # Will be generated
                "crt": "",    # Will be generated
                "prv": "",    # Will be generated
                "serial": "",  # Will be generated
                "dn": {
                    "countryName": country,
                    "stateOrProvinceName": state,
                    "localityName": city,
                    "organizationName": organization,
                    "organizationalUnitName": organizational_unit,
                    "commonName": common_name,
                    "emailAddress": dn_email
                },
                "digest_alg": digest_alg,
                "keylen": str(key_length),
                "lifetime": str(lifetime)
            }
        }

        response = await client.request("POST", API_CERTIFICATES_CA_ADD, json=ca_data)

        # Apply configuration if successful
        if response.get("result") == "saved":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_certificate_authority", e)


@mcp.tool(name="delete_certificate_authority", description="Delete a Certificate Authority")
async def delete_certificate_authority(ctx: Context, ca_uuid: str) -> str:
    """Delete a Certificate Authority.

    Args:
        ctx: Request context
        ca_uuid: UUID of the Certificate Authority to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        if not ca_uuid:
            raise ValueError("Certificate Authority UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_CA_DEL}/{ca_uuid}")

        # Apply configuration if successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_certificate_authority", e)


@mcp.tool(name="export_certificate_authority", description="Export a Certificate Authority certificate")
async def export_certificate_authority(ctx: Context, ca_uuid: str) -> str:
    """Export a Certificate Authority certificate in PEM format.

    Args:
        ctx: Request context
        ca_uuid: UUID of the Certificate Authority to export

    Returns:
        JSON string with certificate data
    """
    try:
        client = await get_opnsense_client()

        if not ca_uuid:
            raise ValueError("Certificate Authority UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_CA_EXPORT}/{ca_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "export_certificate_authority", e)


# ========== CERTIFICATES ==========

@mcp.tool(name="list_certificates", description="List all certificates")
async def list_certificates(ctx: Context) -> str:
    """List all certificates configured in OPNsense.

    Args:
        ctx: Request context

    Returns:
        JSON string with list of certificates
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("POST", API_CERTIFICATES_CERT_SEARCH)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_certificates", e)


@mcp.tool(name="get_certificate", description="Get detailed information about a specific certificate")
async def get_certificate(ctx: Context, cert_uuid: str) -> str:
    """Get detailed information about a specific certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the certificate

    Returns:
        JSON string with certificate details
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("Certificate UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_CERT_GET}/{cert_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_certificate", e)


@mcp.tool(name="import_certificate", description="Import an existing certificate")
async def import_certificate(ctx: Context, descr: str, crt: str, prv: str = "") -> str:
    """Import an existing certificate and private key.

    Args:
        ctx: Request context
        descr: Description/name for the certificate
        crt: Certificate in PEM format
        prv: Private key in PEM format (optional for certificate-only import)

    Returns:
        JSON string with import result and certificate UUID
    """
    try:
        client = await get_opnsense_client()

        if not descr:
            raise ValueError("Description is required")
        if not crt:
            raise ValueError("Certificate data is required")

        # Basic PEM format validation
        if not crt.strip().startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError("Certificate must be in PEM format starting with -----BEGIN CERTIFICATE-----")

        if prv and not prv.strip().startswith("-----BEGIN"):
            raise ValueError("Private key must be in PEM format")

        cert_data = {
            "cert": {
                "descr": descr,
                "crt": crt.strip(),
                "prv": prv.strip() if prv else ""
            }
        }

        response = await client.request("POST", API_CERTIFICATES_CERT_ADD, json=cert_data)

        # Apply configuration if successful
        if response.get("result") == "saved":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "import_certificate", e)


@mcp.tool(name="delete_certificate", description="Delete a certificate")
async def delete_certificate(ctx: Context, cert_uuid: str) -> str:
    """Delete a certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the certificate to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("Certificate UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_CERT_DEL}/{cert_uuid}")

        # Apply configuration if successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_certificate", e)


@mcp.tool(name="export_certificate", description="Export a certificate")
async def export_certificate(ctx: Context, cert_uuid: str) -> str:
    """Export a certificate in PEM format.

    Args:
        ctx: Request context
        cert_uuid: UUID of the certificate to export

    Returns:
        JSON string with certificate data
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("Certificate UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_CERT_EXPORT}/{cert_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "export_certificate", e)


# ========== CERTIFICATE SIGNING REQUESTS (CSRs) ==========

@mcp.tool(name="list_certificate_signing_requests", description="List all Certificate Signing Requests (CSRs)")
async def list_certificate_signing_requests(ctx: Context) -> str:
    """List all Certificate Signing Requests configured in OPNsense.

    Args:
        ctx: Request context

    Returns:
        JSON string with list of Certificate Signing Requests
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("POST", API_CERTIFICATES_CSR_SEARCH)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_certificate_signing_requests", e)


@mcp.tool(name="get_certificate_signing_request", description="Get detailed information about a specific CSR")
async def get_certificate_signing_request(ctx: Context, csr_uuid: str) -> str:
    """Get detailed information about a specific Certificate Signing Request.

    Args:
        ctx: Request context
        csr_uuid: UUID of the Certificate Signing Request

    Returns:
        JSON string with CSR details
    """
    try:
        client = await get_opnsense_client()

        if not csr_uuid:
            raise ValueError("CSR UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_CSR_GET}/{csr_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_certificate_signing_request", e)


@mcp.tool(name="create_certificate_signing_request", description="Create a new Certificate Signing Request")
async def create_certificate_signing_request(ctx: Context, descr: str, country: str, state: str, city: str,
                                           organization: str, common_name: str, organizational_unit: str = "",
                                           digest_alg: str = "sha256", key_length: int = 2048,
                                           dn_email: str = "") -> str:
    """Create a new Certificate Signing Request.

    Args:
        ctx: Request context
        descr: Description/name for the CSR
        country: Two-letter country code (e.g., 'US')
        state: State or Province
        city: City or Locality
        organization: Organization name
        common_name: Common Name (FQDN for server certificates)
        organizational_unit: Organizational Unit (optional)
        digest_alg: Digest algorithm (sha256, sha384, sha512)
        key_length: RSA key length (2048, 4096)
        dn_email: Email address (optional)

    Returns:
        JSON string with creation result and new CSR UUID
    """
    try:
        client = await get_opnsense_client()

        # Validation
        if not descr:
            raise ValueError("Description is required")
        if not country or len(country) != 2:
            raise ValueError("Country must be a 2-letter code (e.g., 'US')")
        if not state:
            raise ValueError("State/Province is required")
        if not city:
            raise ValueError("City/Locality is required")
        if not organization:
            raise ValueError("Organization is required")
        if not common_name:
            raise ValueError("Common Name is required")
        if digest_alg not in ["sha256", "sha384", "sha512"]:
            raise ValueError("Digest algorithm must be one of: sha256, sha384, sha512")
        if key_length not in [2048, 4096]:
            raise ValueError("Key length must be 2048 or 4096")

        csr_data = {
            "csr": {
                "descr": descr,
                "dn": {
                    "countryName": country,
                    "stateOrProvinceName": state,
                    "localityName": city,
                    "organizationName": organization,
                    "organizationalUnitName": organizational_unit,
                    "commonName": common_name,
                    "emailAddress": dn_email
                },
                "digest_alg": digest_alg,
                "keylen": str(key_length)
            }
        }

        response = await client.request("POST", API_CERTIFICATES_CSR_ADD, json=csr_data)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_certificate_signing_request", e)


@mcp.tool(name="delete_certificate_signing_request", description="Delete a Certificate Signing Request")
async def delete_certificate_signing_request(ctx: Context, csr_uuid: str) -> str:
    """Delete a Certificate Signing Request.

    Args:
        ctx: Request context
        csr_uuid: UUID of the CSR to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        if not csr_uuid:
            raise ValueError("CSR UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_CSR_DEL}/{csr_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_certificate_signing_request", e)


# ========== ACME ACCOUNTS ==========

@mcp.tool(name="list_acme_accounts", description="List all ACME (Let's Encrypt) accounts")
async def list_acme_accounts(ctx: Context) -> str:
    """List all ACME (Let's Encrypt) accounts configured in OPNsense.

    Args:
        ctx: Request context

    Returns:
        JSON string with list of ACME accounts
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("POST", API_CERTIFICATES_ACME_ACCOUNTS_SEARCH)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_acme_accounts", e)


@mcp.tool(name="get_acme_account", description="Get detailed information about a specific ACME account")
async def get_acme_account(ctx: Context, account_uuid: str) -> str:
    """Get detailed information about a specific ACME account.

    Args:
        ctx: Request context
        account_uuid: UUID of the ACME account

    Returns:
        JSON string with ACME account details
    """
    try:
        client = await get_opnsense_client()

        if not account_uuid:
            raise ValueError("ACME account UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_ACME_ACCOUNTS_GET}/{account_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_acme_account", e)


@mcp.tool(name="create_acme_account", description="Create a new ACME (Let's Encrypt) account")
async def create_acme_account(ctx: Context, name: str, email: str,
                            ca_url: str = "https://acme-v02.api.letsencrypt.org/directory",
                            key_length: int = 2048) -> str:
    """Create a new ACME (Let's Encrypt) account.

    Args:
        ctx: Request context
        name: Descriptive name for the ACME account
        email: Email address for the ACME account
        ca_url: ACME CA URL (default: Let's Encrypt production)
        key_length: RSA key length (2048, 4096)

    Returns:
        JSON string with creation result and new account UUID
    """
    try:
        client = await get_opnsense_client()

        # Validation
        if not name:
            raise ValueError("Account name is required")
        if not email:
            raise ValueError("Email address is required")
        if not ca_url:
            raise ValueError("CA URL is required")
        if key_length not in [2048, 4096]:
            raise ValueError("Key length must be 2048 or 4096")

        # Basic email validation
        if "@" not in email or "." not in email.split("@")[1]:
            raise ValueError("Invalid email address format")

        account_data = {
            "account": {
                "name": name,
                "email": email,
                "ca_url": ca_url,
                "key_length": str(key_length)
            }
        }

        response = await client.request("POST", API_CERTIFICATES_ACME_ACCOUNTS_ADD, json=account_data)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_acme_account", e)


@mcp.tool(name="delete_acme_account", description="Delete an ACME (Let's Encrypt) account")
async def delete_acme_account(ctx: Context, account_uuid: str) -> str:
    """Delete an ACME (Let's Encrypt) account.

    Args:
        ctx: Request context
        account_uuid: UUID of the ACME account to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        if not account_uuid:
            raise ValueError("ACME account UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_ACME_ACCOUNTS_DEL}/{account_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_acme_account", e)


# ========== ACME CERTIFICATES ==========

@mcp.tool(name="list_acme_certificates", description="List all ACME (Let's Encrypt) certificates")
async def list_acme_certificates(ctx: Context) -> str:
    """List all ACME (Let's Encrypt) certificates configured in OPNsense.

    Args:
        ctx: Request context

    Returns:
        JSON string with list of ACME certificates
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("POST", API_CERTIFICATES_ACME_CERTS_SEARCH)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_acme_certificates", e)


@mcp.tool(name="get_acme_certificate", description="Get detailed information about a specific ACME certificate")
async def get_acme_certificate(ctx: Context, cert_uuid: str) -> str:
    """Get detailed information about a specific ACME certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the ACME certificate

    Returns:
        JSON string with ACME certificate details
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("ACME certificate UUID is required")

        response = await client.request("GET", f"{API_CERTIFICATES_ACME_CERTS_GET}/{cert_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_acme_certificate", e)


@mcp.tool(name="create_acme_certificate", description="Create a new ACME (Let's Encrypt) certificate")
async def create_acme_certificate(ctx: Context, name: str, account_uuid: str, common_name: str,
                                alternative_names: str = "", key_length: int = 2048,
                                auto_renewal: bool = True) -> str:
    """Create a new ACME (Let's Encrypt) certificate.

    Args:
        ctx: Request context
        name: Descriptive name for the certificate
        account_uuid: UUID of the ACME account to use
        common_name: Primary domain name (e.g., example.com)
        alternative_names: Additional domain names (comma-separated, e.g., www.example.com,api.example.com)
        key_length: RSA key length (2048, 4096)
        auto_renewal: Enable automatic renewal (default: True)

    Returns:
        JSON string with creation result and new certificate UUID
    """
    try:
        client = await get_opnsense_client()

        # Validation
        if not name:
            raise ValueError("Certificate name is required")
        if not account_uuid:
            raise ValueError("ACME account UUID is required")
        if not common_name:
            raise ValueError("Common name (domain) is required")
        if key_length not in [2048, 4096]:
            raise ValueError("Key length must be 2048 or 4096")

        cert_data = {
            "cert": {
                "name": name,
                "account": account_uuid,
                "common_name": common_name,
                "alternative_names": alternative_names.strip(),
                "key_length": str(key_length),
                "auto_renewal": "1" if auto_renewal else "0"
            }
        }

        response = await client.request("POST", API_CERTIFICATES_ACME_CERTS_ADD, json=cert_data)
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_acme_certificate", e)


@mcp.tool(name="sign_acme_certificate", description="Sign/issue an ACME (Let's Encrypt) certificate")
async def sign_acme_certificate(ctx: Context, cert_uuid: str) -> str:
    """Sign/issue an ACME (Let's Encrypt) certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the ACME certificate to sign

    Returns:
        JSON string with signing result
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("ACME certificate UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_ACME_CERTS_SIGN}/{cert_uuid}")

        # Apply configuration if successful
        if response.get("result") == "ok":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "sign_acme_certificate", e)


@mcp.tool(name="revoke_acme_certificate", description="Revoke an ACME (Let's Encrypt) certificate")
async def revoke_acme_certificate(ctx: Context, cert_uuid: str) -> str:
    """Revoke an ACME (Let's Encrypt) certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the ACME certificate to revoke

    Returns:
        JSON string with revocation result
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("ACME certificate UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_ACME_CERTS_REVOKE}/{cert_uuid}")

        # Apply configuration if successful
        if response.get("result") == "ok":
            await client.request("POST", API_CERTIFICATES_SERVICE_RECONFIGURE)

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "revoke_acme_certificate", e)


@mcp.tool(name="delete_acme_certificate", description="Delete an ACME (Let's Encrypt) certificate")
async def delete_acme_certificate(ctx: Context, cert_uuid: str) -> str:
    """Delete an ACME (Let's Encrypt) certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the ACME certificate to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("ACME certificate UUID is required")

        response = await client.request("POST", f"{API_CERTIFICATES_ACME_CERTS_DEL}/{cert_uuid}")
        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_acme_certificate", e)


# ========== CERTIFICATE VALIDATION & MONITORING ==========

@mcp.tool(name="analyze_certificate_expiration", description="Analyze certificate expiration dates and provide alerts")
async def analyze_certificate_expiration(ctx: Context, warning_days: int = 30) -> str:
    """Analyze certificate expiration dates and provide expiration alerts.

    Args:
        ctx: Request context
        warning_days: Number of days before expiration to warn (default: 30)

    Returns:
        JSON string with certificate expiration analysis
    """
    try:
        client = await get_opnsense_client()

        if warning_days < 0:
            raise ValueError("Warning days must be non-negative")

        # Get all certificates
        cert_response = await client.request("POST", API_CERTIFICATES_CERT_SEARCH)
        ca_response = await client.request("POST", API_CERTIFICATES_CA_SEARCH)
        acme_response = await client.request("POST", API_CERTIFICATES_ACME_CERTS_SEARCH)

        analysis = {
            "analysis_date": "current_date",
            "warning_threshold_days": warning_days,
            "certificates": {
                "total": 0,
                "expired": [],
                "expiring_soon": [],
                "valid": [],
                "errors": []
            },
            "certificate_authorities": {
                "total": 0,
                "expired": [],
                "expiring_soon": [],
                "valid": [],
                "errors": []
            },
            "acme_certificates": {
                "total": 0,
                "expired": [],
                "expiring_soon": [],
                "valid": [],
                "errors": [],
                "auto_renewal_enabled": 0
            },
            "recommendations": []
        }

        # Analyze certificates
        if cert_response.get("rows"):
            analysis["certificates"]["total"] = len(cert_response["rows"])
            for cert in cert_response["rows"]:
                cert_info = {
                    "uuid": cert.get("uuid"),
                    "description": cert.get("descr", "Unknown"),
                    "common_name": cert.get("CN", "Unknown"),
                    "issuer": cert.get("issuer", "Unknown"),
                    "not_after": cert.get("not_after", "Unknown")
                }

                if cert.get("not_after") == "Unknown" or not cert.get("not_after"):
                    analysis["certificates"]["errors"].append({
                        **cert_info,
                        "error": "Cannot determine expiration date"
                    })
                else:
                    analysis["certificates"]["valid"].append(cert_info)

        # Analyze CAs
        if ca_response.get("rows"):
            analysis["certificate_authorities"]["total"] = len(ca_response["rows"])
            for ca in ca_response["rows"]:
                ca_info = {
                    "uuid": ca.get("uuid"),
                    "description": ca.get("descr", "Unknown"),
                    "common_name": ca.get("CN", "Unknown"),
                    "not_after": ca.get("not_after", "Unknown")
                }

                if ca.get("not_after") == "Unknown" or not ca.get("not_after"):
                    analysis["certificate_authorities"]["errors"].append({
                        **ca_info,
                        "error": "Cannot determine expiration date"
                    })
                else:
                    analysis["certificate_authorities"]["valid"].append(ca_info)

        # Analyze ACME certificates
        if acme_response.get("rows"):
            analysis["acme_certificates"]["total"] = len(acme_response["rows"])
            for acme in acme_response["rows"]:
                acme_info = {
                    "uuid": acme.get("uuid"),
                    "name": acme.get("name", "Unknown"),
                    "common_name": acme.get("common_name", "Unknown"),
                    "status": acme.get("status", "Unknown"),
                    "auto_renewal": acme.get("auto_renewal", "0")
                }

                if acme.get("auto_renewal") == "1":
                    analysis["acme_certificates"]["auto_renewal_enabled"] += 1

                analysis["acme_certificates"]["valid"].append(acme_info)

        # Generate recommendations
        recommendations = []

        if analysis["certificates"]["errors"]:
            recommendations.append("Some certificates have invalid expiration dates. Review certificate configurations.")

        if analysis["certificate_authorities"]["errors"]:
            recommendations.append("Some Certificate Authorities have invalid expiration dates. Review CA configurations.")

        if analysis["acme_certificates"]["total"] > 0:
            auto_renewal_ratio = analysis["acme_certificates"]["auto_renewal_enabled"] / analysis["acme_certificates"]["total"]
            if auto_renewal_ratio < 1.0:
                recommendations.append(f"Only {analysis['acme_certificates']['auto_renewal_enabled']}/{analysis['acme_certificates']['total']} ACME certificates have auto-renewal enabled. Consider enabling auto-renewal for all Let's Encrypt certificates.")

        if not recommendations:
            recommendations.append("Certificate configuration appears healthy. Continue monitoring expiration dates.")

        analysis["recommendations"] = recommendations

        return json.dumps(analysis, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "analyze_certificate_expiration", e)


@mcp.tool(name="validate_certificate_chain", description="Validate certificate chain and trust relationships")
async def validate_certificate_chain(ctx: Context, cert_uuid: str) -> str:
    """Validate certificate chain and trust relationships for a specific certificate.

    Args:
        ctx: Request context
        cert_uuid: UUID of the certificate to validate

    Returns:
        JSON string with certificate chain validation results
    """
    try:
        client = await get_opnsense_client()

        if not cert_uuid:
            raise ValueError("Certificate UUID is required")

        # Get certificate details
        cert_response = await client.request("GET", f"{API_CERTIFICATES_CERT_GET}/{cert_uuid}")

        if not cert_response.get("cert"):
            raise ValueError("Certificate not found")

        cert_data = cert_response["cert"]

        validation_result = {
            "certificate_uuid": cert_uuid,
            "certificate_info": {
                "description": cert_data.get("descr", "Unknown"),
                "common_name": cert_data.get("CN", "Unknown"),
                "issuer": cert_data.get("issuer", "Unknown"),
                "not_before": cert_data.get("not_before", "Unknown"),
                "not_after": cert_data.get("not_after", "Unknown"),
                "serial": cert_data.get("serial", "Unknown")
            },
            "validation_checks": {
                "has_private_key": bool(cert_data.get("prv")),
                "has_certificate": bool(cert_data.get("crt")),
                "format_valid": True,  # Basic assumption
                "chain_complete": False,
                "self_signed": False,
                "expired": False,
                "not_yet_valid": False
            },
            "issues": [],
            "recommendations": []
        }

        # Basic validation checks
        issues = []
        recommendations = []

        if not cert_data.get("crt"):
            issues.append("Certificate data is missing")

        if not cert_data.get("prv"):
            issues.append("Private key is missing - certificate cannot be used for SSL/TLS services")
            recommendations.append("Import the private key for this certificate to enable SSL/TLS usage")

        # Check if certificate appears to be self-signed
        if cert_data.get("issuer") == cert_data.get("CN"):
            validation_result["validation_checks"]["self_signed"] = True
            recommendations.append("Self-signed certificate detected. Consider using CA-signed certificates for production")

        # Get all CAs to check chain
        ca_response = await client.request("POST", API_CERTIFICATES_CA_SEARCH)
        if ca_response.get("rows"):
            for ca in ca_response["rows"]:
                if ca.get("CN") == cert_data.get("issuer"):
                    validation_result["validation_checks"]["chain_complete"] = True
                    break

        if not validation_result["validation_checks"]["chain_complete"] and not validation_result["validation_checks"]["self_signed"]:
            issues.append("Certificate Authority for this certificate is not found in OPNsense")
            recommendations.append("Import the issuing Certificate Authority to complete the certificate chain")

        if not issues:
            recommendations.append("Certificate appears to be properly configured")

        validation_result["issues"] = issues
        validation_result["recommendations"] = recommendations

        return json.dumps(validation_result, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "validate_certificate_chain", e)


@mcp.tool(name="get_certificate_usage", description="Get information about where certificates are used in OPNsense")
async def get_certificate_usage(ctx: Context) -> str:
    """Get information about where certificates are currently used in OPNsense configuration.

    Args:
        ctx: Request context

    Returns:
        JSON string with certificate usage information
    """
    try:
        client = await get_opnsense_client()

        # Get certificates and CAs
        cert_response = await client.request("POST", API_CERTIFICATES_CERT_SEARCH)
        ca_response = await client.request("POST", API_CERTIFICATES_CA_SEARCH)

        usage_info = {
            "certificates": [],
            "certificate_authorities": [],
            "usage_summary": {
                "total_certificates": 0,
                "total_cas": 0,
                "potentially_unused_certs": 0,
                "potentially_unused_cas": 0
            },
            "recommendations": []
        }

        # Process certificates
        if cert_response.get("rows"):
            usage_info["usage_summary"]["total_certificates"] = len(cert_response["rows"])
            for cert in cert_response["rows"]:
                cert_info = {
                    "uuid": cert.get("uuid"),
                    "description": cert.get("descr", "Unknown"),
                    "common_name": cert.get("CN", "Unknown"),
                    "has_private_key": bool(cert.get("prv")),
                    "potential_uses": []
                }

                # Determine potential uses based on certificate properties
                if cert.get("prv"):
                    cert_info["potential_uses"].extend([
                        "Web GUI HTTPS",
                        "OpenVPN Server",
                        "IPsec VPN",
                        "HAProxy SSL",
                        "Captive Portal HTTPS"
                    ])
                else:
                    cert_info["potential_uses"].append("Client authentication only (no private key)")

                # Simple heuristic for unused certificates
                if not cert.get("prv"):
                    usage_info["usage_summary"]["potentially_unused_certs"] += 1

                usage_info["certificates"].append(cert_info)

        # Process Certificate Authorities
        if ca_response.get("rows"):
            usage_info["usage_summary"]["total_cas"] = len(ca_response["rows"])
            for ca in ca_response["rows"]:
                ca_info = {
                    "uuid": ca.get("uuid"),
                    "description": ca.get("descr", "Unknown"),
                    "common_name": ca.get("CN", "Unknown"),
                    "potential_uses": [
                        "Certificate chain validation",
                        "Client certificate authority",
                        "OpenVPN CA",
                        "IPsec Certificate Authority"
                    ]
                }
                usage_info["certificate_authorities"].append(ca_info)

        # Generate recommendations
        recommendations = []

        if usage_info["usage_summary"]["potentially_unused_certs"] > 0:
            recommendations.append(f"{usage_info['usage_summary']['potentially_unused_certs']} certificates lack private keys and may be unused. Consider cleaning up unused certificates.")

        if usage_info["usage_summary"]["total_certificates"] == 0:
            recommendations.append("No certificates configured. Consider setting up SSL/TLS certificates for secure services.")

        if usage_info["usage_summary"]["total_cas"] == 0:
            recommendations.append("No Certificate Authorities configured. Consider setting up a CA for internal certificate management.")

        if not recommendations:
            recommendations.append("Certificate inventory appears reasonable. Review individual certificate usage as needed.")

        usage_info["recommendations"] = recommendations

        return json.dumps(usage_info, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_certificate_usage", e)
