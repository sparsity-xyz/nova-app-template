"""Centralized configuration for the Nova app template enclave.

This project uses a single config module so it's obvious where to set:
- auth chain (Nova Registry / KMS authorization)
- business chain (application logic and contract writes)
- app-wallet + KMS proof defaults
- oracle update behavior

This module defines defaults only. Runtime overrides are resolved in
`chain.py` and `nova_python_sdk.env`, not here.

Relevant override env vars:
- `IN_ENCLAVE`
- `ODYN_API_BASE_URL` / `ODYN_ENDPOINT`
- `ETHEREUM_MAINNET_RPC_URL` / `BUSINESS_CHAIN_RPC_URL`
- `NOVA_AUTH_CHAIN_RPC_URL` / `AUTH_CHAIN_RPC_URL`
"""

from __future__ import annotations
# =============================================================================
# Auth Chain (Registry / KMS authorization path)
# =============================================================================

# Chain where NovaAppRegistry lives (used for app-wallet proof metadata).
AUTH_CHAIN_NAME: str = "base-sepolia"
AUTH_CHAIN_ID: int = 84532

# Public RPC used as a diagnostic fallback when auth-chain Helios is unavailable.
AUTH_CHAIN_PUBLIC_RPC_URL: str = "https://sepolia.base.org"

# Local development should prefer the public mockup Helios endpoint so behavior
# stays close to the final enclave runtime instead of bypassing Helios entirely.
AUTH_CHAIN_MOCK_HELIOS_RPC_URL: str = "http://odyn.sparsity.cloud:18545"

# In enclave mode (IN_ENCLAVE=true), the auth-chain Helios instance is expected
# to be available at this local endpoint (configured in enclaver.yaml).
AUTH_CHAIN_ENCLAVE_HELIOS_RPC_URL: str = "http://127.0.0.1:18545"




# =============================================================================
# Business Chain (application logic path)
# =============================================================================

# This template's business chain is Ethereum mainnet.
ETHEREUM_MAINNET_CHAIN_NAME: str = "ethereum-mainnet"
ETHEREUM_MAINNET_CHAIN_ID: int = 1

# Prefer the mockup Helios endpoint during local development.
ETHEREUM_MAINNET_MOCK_HELIOS_RPC_URL: str = "http://odyn.sparsity.cloud:18546"

# Public RPCs are kept as explicit operator-facing fallbacks.
ETHEREUM_MAINNET_PUBLIC_RPC_URL: str = "https://ethereum-rpc.publicnode.com"
ETHEREUM_MAINNET_PUBLIC_RPC_FALLBACK_URL: str = "https://eth.drpc.org"

# In enclave mode (IN_ENCLAVE=true), the business-chain Helios instance is
# expected to be available at this local endpoint (configured in enclaver.yaml).
ETHEREUM_MAINNET_ENCLAVE_HELIOS_RPC_URL: str = "http://127.0.0.1:18546"

# Generic aliases used throughout the template app logic.
BUSINESS_CHAIN_NAME: str = ETHEREUM_MAINNET_CHAIN_NAME
BUSINESS_CHAIN_ID: int = ETHEREUM_MAINNET_CHAIN_ID
AUTH_CHAIN_LOCAL_RPC_URL: str = AUTH_CHAIN_ENCLAVE_HELIOS_RPC_URL
BUSINESS_CHAIN_LOCAL_RPC_URL: str = ETHEREUM_MAINNET_ENCLAVE_HELIOS_RPC_URL

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
# Oracle demo config
# =============================================================================

# Periodic update interval (minutes)
ORACLE_PRICE_UPDATE_MINUTES: int = 15

# For event monitoring, scan last N blocks each poll.
ORACLE_EVENT_POLL_LOOKBACK_BLOCKS: int = 1000
