"""
=============================================================================
Background Tasks (tasks.py)
=============================================================================

Define your periodic background jobs here.

┌─────────────────────────────────────────────────────────────────────────────┐
│  MODIFY THIS FILE                                                           │
│  Add your own background tasks / cron jobs here.                            │
└─────────────────────────────────────────────────────────────────────────────┘

How it works:
    - background_task() is called every 5 minutes by the scheduler
    - You can access app_state and odyn after init() is called
    - Modify the interval in app.py if needed

Example use cases:
    - Auto-save state to S3 with hash on-chain
    - Periodic data sync from external APIs
    - Listen and respond to on-chain events
    - Scheduled on-chain transactions
"""

import json
import logging
from datetime import datetime
from datetime import timezone
from typing import Optional, TYPE_CHECKING, Dict, Any

import requests
from eth_hash.auto import keccak

from chain import compute_state_hash, sign_update_state_hash, sign_update_eth_price, rpc_call_with_failover
from config import (
    RPC_URL,
    CONTRACT_ADDRESS,
    CHAIN_ID,
    BROADCAST_TX,
    ORACLE_PRICE_UPDATE_MINUTES,
    ORACLE_EVENT_POLL_LOOKBACK_BLOCKS,
)

# Type hint for Odyn (actual import would cause circular dependency)
if TYPE_CHECKING:
    from odyn import Odyn

logger = logging.getLogger("nova-app.tasks")

# =============================================================================
# Shared References (set by app.py during startup)
# =============================================================================
app_state: Optional[dict] = None
odyn: Optional["Odyn"] = None

# =============================================================================
# Configuration
# =============================================================================
# See config.py for all configuration and defaults.


def init(state_ref: dict, odyn_ref: "Odyn"):
    """
    Initialize the tasks module with shared references.
    
    Called by app.py during startup. Do not call directly.
    
    Args:
        state_ref: Reference to app_state dict
        odyn_ref: Reference to Odyn instance
    """
    global app_state, odyn
    app_state = state_ref
    odyn = odyn_ref
    logger.info("Tasks module initialized")


# =============================================================================
# Helper Functions
# =============================================================================


def fetch_external_data() -> Optional[dict]:
    """
    Example: Fetch data from an external API.
    
    Replace this with your actual data source:
    - Price feeds (Chainlink, Binance, etc.)
    - Weather data
    - Sports scores
    - Any public API
    """
    try:
        # Example: Fetch ETH price from a public API
        # Replace with your actual data source
        response = requests.get(
            "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch external data: {e}")
        return None


def fetch_eth_price_usd() -> int:
    """Fetch ETH/USD spot price as integer USD (no decimals)."""
    response = requests.get(
        "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
        timeout=10,
    )
    response.raise_for_status()
    return int(response.json()["ethereum"]["usd"])


def update_eth_price_on_chain(*, request_id: int, reason: str) -> Dict[str, Any]:
    if not (odyn and CONTRACT_ADDRESS):
        raise RuntimeError("Oracle not configured (missing odyn or CONTRACT_ADDRESS)")

    price_usd = fetch_eth_price_usd()
    updated_at = int(datetime.now(tz=timezone.utc).timestamp())

    signed = sign_update_eth_price(
        odyn=odyn,
        contract_address=CONTRACT_ADDRESS,
        chain_id=CHAIN_ID,
        rpc_url=RPC_URL,
        request_id=request_id,
        price_usd=price_usd,
        updated_at=updated_at,
        broadcast=BROADCAST_TX,
    )

    oracle_state = app_state.setdefault("data", {}).setdefault("oracle", {}) if app_state else {}
    oracle_state["last_price_usd"] = price_usd
    oracle_state["last_updated_at"] = updated_at
    oracle_state["last_reason"] = reason
    oracle_state["last_tx"] = signed
    oracle_state["last_run"] = datetime.utcnow().isoformat() + "Z"

    return {
        "price_usd": price_usd,
        "updated_at": updated_at,
        "request_id": request_id,
        "tx": signed,
        "broadcast": BROADCAST_TX,
        "contract_address": CONTRACT_ADDRESS,
    }


def update_state_hash_on_chain(state_hash: str) -> Optional[str]:
    """
    Sign a transaction to update state hash on-chain.
    
    Args:
        state_hash: bytes32 hex string
        
    Returns:
        Raw signed transaction (ready for broadcast), or None on failure
    """
    if not odyn or not CONTRACT_ADDRESS:
        return None
    
    try:
        signed = sign_update_state_hash(
            odyn=odyn,
            contract_address=CONTRACT_ADDRESS,
            chain_id=CHAIN_ID,
            rpc_url=RPC_URL,
            state_hash=state_hash,
            broadcast=BROADCAST_TX,
        )
        logger.info(f"Signed state hash update tx: {signed['transaction_hash']}")
        return signed.get("raw_transaction")
    except Exception as e:
        logger.error(f"Failed to sign state hash tx: {e}")
        return None


# =============================================================================
# Main Background Task (MODIFY BELOW)
# =============================================================================

def background_task():
    """
    Main background task - runs every 5 minutes.
    
    ┌─────────────────────────────────────────────────────────────────────────┐
    │  MODIFY THIS FUNCTION                                                   │
    │  Add your own periodic logic here.                                      │
    └─────────────────────────────────────────────────────────────────────────┘
    
    This example demonstrates:
    1. Fetching external data (e.g., price feed)
    2. Storing data to S3
    3. Computing hash and preparing on-chain update
    """
    if app_state is None:
        logger.warning("Tasks not initialized yet")
        return
    
    # --- Track task execution ---
    app_state["cron_counter"] = app_state.get("cron_counter", 0) + 1
    app_state["last_cron_run"] = datetime.utcnow().isoformat() + "Z"
    
    logger.info(f"Cron job #{app_state['cron_counter']} at {app_state['last_cron_run']}")
    
    # --- Example 1: Fetch external data ---
    external_data = fetch_external_data()
    if external_data:
        app_state["data"]["last_external_data"] = external_data
        app_state["data"]["last_fetch_time"] = app_state["last_cron_run"]
        logger.info(f"Fetched external data: {external_data}")
    
    # --- Example 2: Save state to S3 ---
    try:
        if app_state.get("initialized") and odyn:
            state_data = app_state.get("data", {})
            json_bytes = json.dumps(state_data).encode('utf-8')
            success = odyn.s3_put("app_state.json", json_bytes)
            if success:
                logger.info("Auto-saved state to S3")
                
                # --- Example 3: Compute hash and prepare on-chain update ---
                state_hash = compute_state_hash(state_data)
                app_state["data"]["last_state_hash"] = state_hash
                logger.info(f"State hash: {state_hash}")
                
                # Optionally sign tx for on-chain update (don't broadcast here)
                raw_tx = update_state_hash_on_chain(state_hash)
                if raw_tx:
                    app_state["data"]["pending_tx"] = raw_tx
            else:
                logger.warning("State save returned False")
    except Exception as e:
        logger.error(f"Cron auto-save failed: {e}")

    # On-chain event polling is scheduled separately (see app.py)



# =============================================================================
# On-Chain Event Listener (Optional Pattern)
# =============================================================================

def poll_contract_events():
    """Poll for on-chain events and respond.

    - Listens for StateUpdateRequested(bytes32,address) and anchors local state hash.
    - Listens for EthPriceUpdateRequested(uint256,address) and updates ETH price on-chain.

    Logs are stored in app_state["data"]["event_monitor"] for frontend display.
    """
    if not (odyn and app_state and CONTRACT_ADDRESS):
        return

    # Initialize monitor state early
    monitor = app_state.setdefault("data", {}).setdefault("event_monitor", {})

    def add_log(msg: str):
        """Add a log entry to event monitor logs."""
        logs = monitor.setdefault("logs", [])
        timestamp = datetime.utcnow().isoformat() + "Z"
        logs.append({"time": timestamp, "message": msg})
        # Keep only last 100 logs
        if len(logs) > 100:
            monitor["logs"] = logs[-100:]
        monitor["last_poll"] = timestamp

    # Use rpc_call_with_failover from chain.py for automatic failover
    rpc_call = rpc_call_with_failover

    try:
        current_block_hex = rpc_call("eth_blockNumber", [])
        current_block = int(current_block_hex, 16)
    except Exception as e:
        add_log(f"✗ Failed to get current block: {e}")
        return

    last_block = app_state["data"].get("last_processed_block")
    if last_block is None:
        last_block = max(current_block - 1, 0)

    # Update monitor state
    monitor = app_state.setdefault("data", {}).setdefault("event_monitor", {})
    monitor["current_block"] = current_block
    monitor["last_processed_block"] = last_block
    monitor["contract_address"] = CONTRACT_ADDRESS

    # Event signature: StateUpdateRequested(bytes32,address)
    topic0 = "0x" + keccak(b"StateUpdateRequested(bytes32,address)").hex()

    logs = rpc_call(
        "eth_getLogs",
        [{
            "fromBlock": hex(last_block + 1),
            "toBlock": hex(current_block),
            "address": CONTRACT_ADDRESS,
            "topics": [topic0],
        }],
    )

    if logs:
        app_state["data"]["last_event_count"] = app_state["data"].get("last_event_count", 0) + len(logs)
        add_log(f"Found {len(logs)} StateUpdateRequested event(s)")

        state_hash = compute_state_hash(app_state.get("data", {}))
        app_state["data"]["last_state_hash"] = state_hash

        signed = sign_update_state_hash(
            odyn=odyn,
            contract_address=CONTRACT_ADDRESS,
            chain_id=CHAIN_ID,
            rpc_url=RPC_URL,
            state_hash=state_hash,
            broadcast=BROADCAST_TX,
        )
        app_state["data"]["last_event_anchor_tx"] = signed
        add_log(f"✓ State hash updated on-chain: {state_hash[:18]}...")

    # ---------------------------------------------------------------------
    # Oracle: EthPriceUpdateRequested(uint256,address)
    # ---------------------------------------------------------------------
    oracle_topic0 = "0x" + keccak(b"EthPriceUpdateRequested(uint256,address)").hex()

    try:
        oracle_logs = rpc_call(
            "eth_getLogs",
            [{
                "fromBlock": hex(max(current_block - ORACLE_EVENT_POLL_LOOKBACK_BLOCKS, 0)),
                "toBlock": hex(current_block),
                "address": CONTRACT_ADDRESS,
                "topics": [oracle_topic0],
            }],
        )
    except Exception as e:
        add_log(f"✗ Failed to fetch oracle events: {e}")
        oracle_logs = []

    oracle_state = app_state.setdefault("data", {}).setdefault("oracle", {})
    handled = oracle_state.setdefault("handled_requests", {})

    # Count pending requests
    pending_count = 0
    for log in oracle_logs or []:
        request_id_hex = log.get("topics", [None, None])[1]
        if request_id_hex:
            request_id = int(request_id_hex, 16)
            if str(request_id) not in handled:
                pending_count += 1

    if pending_count > 0:
        add_log(f"Found {pending_count} pending EthPriceUpdateRequested event(s)")

    # Store recent events for frontend display
    recent_events = []
    for log in oracle_logs or []:
        request_id_hex = log.get("topics", [None, None])[1]
        if request_id_hex:
            request_id = int(request_id_hex, 16)
            block_num = int(log.get("blockNumber", "0x0"), 16)
            tx_hash = log.get("transactionHash", "")
            is_handled = str(request_id) in handled
            recent_events.append({
                "type": "EthPriceUpdateRequested",
                "request_id": request_id,
                "block_number": block_num,
                "tx_hash": tx_hash,
                "handled": is_handled,
            })
    monitor["recent_events"] = recent_events
    monitor["pending_count"] = pending_count

    for log in oracle_logs or []:
        try:
            request_id_hex = log.get("topics", [None, None])[1]
            if not request_id_hex:
                continue
            request_id = int(request_id_hex, 16)
            request_id_key = str(request_id)
            if request_id_key in handled:
                continue

            add_log(f"Processing request #{request_id}...")
            result = update_eth_price_on_chain(request_id=request_id, reason="onchain_event")
            handled[request_id_key] = {
                "handled_at": datetime.utcnow().isoformat() + "Z",
                "tx": result.get("tx"),
                "price_usd": result.get("price_usd"),
                "updated_at": result.get("updated_at"),
            }
            add_log(f"✓ Request #{request_id}: Updated price ${result.get('price_usd')}")
            # Update recent_events to mark as handled
            for ev in monitor.get("recent_events", []):
                if ev.get("request_id") == request_id:
                    ev["handled"] = True
                    ev["price_usd"] = result.get("price_usd")
        except Exception as e:
            add_log(f"✗ Request #{request_id}: Failed - {e}")
            logger.warning(f"Failed handling oracle request log: {e}")

    app_state["data"]["last_processed_block"] = current_block


def oracle_periodic_update():
    """Periodic ETH price update (default every 15 minutes)."""
    if app_state is None:
        return
    try:
        update_eth_price_on_chain(request_id=0, reason="periodic")
    except Exception as e:
        oracle_state = app_state.setdefault("data", {}).setdefault("oracle", {})
        oracle_state["last_error"] = str(e)
        logger.warning(f"Periodic oracle update failed: {e}")

