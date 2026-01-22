"""QERDS Trust service.

Signing, sealing, and timestamping service providing:
- Provider attestation (seal/signature) for evidence objects
- Trustworthy time attestation (RFC 3161 or similar)
- Key Encryption Key (KEK) custody for data-at-rest encryption
- HSM/QSCD integration via PKCS#11 in qualified mode

IMPORTANT: This service supports two modes:
- non_qualified: Software keys for development/testing only (clearly labeled)
- qualified: Keys only through certified HSM via PKCS#11 (no software fallback)

Never claim qualified status without proper HSM integration and operator certification.
"""
