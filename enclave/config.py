"""Centralized configuration for the Nova app template enclave.

This project uses a single config module so it's obvious where to set:
- app contract address
- RPC URL / chain ID
- oracle update behavior

Per your request, this file does NOT read environment variables.
Edit these constants directly.
"""

from __future__ import annotations
from typing import List

# =============================================================================
# Chain / contract config
# =============================================================================

# JSON-RPC endpoints (Base Sepolia) - multiple URLs for failover
# The first available URL will be used; if it fails, the next one is tried.
RPC_URLS: List[str] = [
    "https://sepolia.base.org",
    "https://base-sepolia.blockpi.network/v1/rpc/public",
    "https://base-sepolia-rpc.publicnode.com",
]

# Primary RPC URL (kept for backward compatibility, uses first from RPC_URLS)
RPC_URL: str = RPC_URLS[0] if RPC_URLS else "https://sepolia.base.org"

# Chain ID (Base Sepolia default)
CHAIN_ID: int = 84532

# Deployed app contract address (ETHPriceOracleApp / NovaAppBase-derived)
# Example: "0x1234..."
CONTRACT_ADDRESS: str = "0x6Ab9DbaA6d57ecb3C9145c7e08627940aab4cf80"

# If true, enclave will broadcast signed transactions to RPC.
# If false, enclave returns raw signed txs.
BROADCAST_TX: bool = False

# Storage demo: anchor state hash on writes
ANCHOR_ON_WRITE: bool = True


# =============================================================================
# Oracle demo config
# =============================================================================

# Periodic update interval (minutes)
ORACLE_PRICE_UPDATE_MINUTES: int = 15

# For event monitoring, scan last N blocks each poll.
ORACLE_EVENT_POLL_LOOKBACK_BLOCKS: int = 1000
