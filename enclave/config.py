"""Centralized configuration for the Nova app template enclave.

This project uses a single config module so it's obvious where to set:
- auth chain (Nova Registry / KMS authorization)
- business chain (application logic and contract writes)
- app-wallet + KMS proof defaults
- oracle update behavior

Per your request, this file does NOT read environment variables.
Edit these constants directly.
"""

from __future__ import annotations
# =============================================================================
# Auth Chain (Registry / KMS authorization path)
# =============================================================================

# Chain where NovaAppRegistry lives (used for app-wallet proof metadata).
AUTH_CHAIN_NAME: str = "base-sepolia"
AUTH_CHAIN_ID: int = 84532
AUTH_CHAIN_RPC_URL: str = "https://sepolia.base.org"
# In enclave mode (IN_ENCLAVE=true), this app expects the auth chain Helios
# instance to be available at this local endpoint (configured in enclaver.yaml).
AUTH_CHAIN_LOCAL_RPC_URL: str = "http://127.0.0.1:18545"

# Nova App Registry contract used by app-wallet binding proof.
NOVA_APP_REGISTRY_ADDRESS: str = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"


# =============================================================================
# Business Chain (application logic path)
# =============================================================================

# Business chain is Ethereum mainnet by default.
BUSINESS_CHAIN_NAME: str = "ethereum-mainnet"
BUSINESS_CHAIN_ID: int = 1

# Used outside enclave mode.
BUSINESS_CHAIN_DIRECT_RPC_URL: str = "https://eth.llamarpc.com"
# In enclave mode (IN_ENCLAVE=true), this app expects the business chain Helios
# instance to be available at this local endpoint (configured in enclaver.yaml).
BUSINESS_CHAIN_LOCAL_RPC_URL: str = "http://127.0.0.1:18546"

# Backward-compatible alias used by existing helper functions.
CHAIN_ID: int = BUSINESS_CHAIN_ID

# Deployed app contract address (ETHPriceOracleApp / NovaAppBase-derived)
# Example: "0x1234...". Keep empty until deployed.
CONTRACT_ADDRESS: str = ""

# If true, enclave will broadcast signed transactions to RPC.
# If false, enclave returns raw signed txs.
BROADCAST_TX: bool = False

# Storage demo: anchor state hash on writes
ANCHOR_ON_WRITE: bool = True

# S3 encryption mode expectation.
# Actual encryption is enforced by `enclaver.yaml` storage.s3.encryption.mode.
S3_ENCRYPTION_MODE: str = "kms"
S3_ENCRYPTION_KEY_SCOPE: str = "object"
S3_ENCRYPTION_AAD_MODE: str = "key"
S3_ENCRYPTION_KEY_VERSION: str = "v1"
S3_ENCRYPTION_ACCEPT_PLAINTEXT: bool = True


# =============================================================================
# KMS / App Wallet defaults
# =============================================================================

# Update to your actual App + Version once enrolled.
APP_ID: int = 0
APP_VERSION_ID: int = 0

# Default validity for generated app-wallet proofs.
APP_WALLET_PROOF_TTL_SECONDS: int = 3600


# =============================================================================
# Oracle demo config
# =============================================================================

# Periodic update interval (minutes)
ORACLE_PRICE_UPDATE_MINUTES: int = 15

# For event monitoring, scan last N blocks each poll.
ORACLE_EVENT_POLL_LOOKBACK_BLOCKS: int = 1000
