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

# Chain ID (Base Sepolia default)
CHAIN_ID: int = 84532

# Deployed app contract address (ETHPriceOracleApp / NovaAppBase-derived)
# Example: "0x1234..."
CONTRACT_ADDRESS: str = "0x66Ac7d512e0df4abaF822454d08067D3EAAf3AB4"

# If true, enclave will broadcast signed transactions to RPC.
# If false, enclave returns raw signed txs.
BROADCAST_TX: bool = True

# Storage demo: anchor state hash on writes
ANCHOR_ON_WRITE: bool = True


# =============================================================================
# Oracle demo config
# =============================================================================

# Periodic update interval (minutes)
ORACLE_PRICE_UPDATE_MINUTES: int = 15

# For event monitoring, scan last N blocks each poll.
ORACLE_EVENT_POLL_LOOKBACK_BLOCKS: int = 1000
