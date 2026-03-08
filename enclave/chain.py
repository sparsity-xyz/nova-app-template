"""
App-specific chain helpers built on top of `nova_python_sdk.rpc`.

Keep shared RPC transport and environment switching in `nova_python_sdk/`.
Keep contract selectors, ABI-specific reads, and transaction builders here.

Runtime endpoint precedence:
- Business chain: `ETHEREUM_MAINNET_RPC_URL` -> `BUSINESS_CHAIN_RPC_URL` ->
  enclave-local Helios (`127.0.0.1:18546`) -> public mockup Helios
  (`odyn.sparsity.cloud:18546`)
- Auth chain: `NOVA_AUTH_CHAIN_RPC_URL` -> `AUTH_CHAIN_RPC_URL` ->
  enclave-local Helios (`127.0.0.1:18545`) -> public mockup Helios
  (`odyn.sparsity.cloud:18545`)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional

from eth_hash.auto import keccak
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import (
    AUTH_CHAIN_ID,
    AUTH_CHAIN_ENCLAVE_HELIOS_RPC_URL,
    AUTH_CHAIN_MOCK_HELIOS_RPC_URL,
    AUTH_CHAIN_NAME,
    AUTH_CHAIN_PUBLIC_RPC_URL,
    BUSINESS_CHAIN_ID,
    BUSINESS_CHAIN_NAME,
    ETHEREUM_MAINNET_ENCLAVE_HELIOS_RPC_URL,
    ETHEREUM_MAINNET_MOCK_HELIOS_RPC_URL,
    ETHEREUM_MAINNET_PUBLIC_RPC_URL,
)
from nova_python_sdk.env import in_enclave, resolve_runtime_url
from nova_python_sdk.rpc import ChainRpc, fetch_block_number

logger = logging.getLogger("nova-app.chain")

CONFIRMATION_DEPTH: int = 6

_chain = ChainRpc(
    enclave_rpc_url=ETHEREUM_MAINNET_ENCLAVE_HELIOS_RPC_URL,
    dev_rpc_url=ETHEREUM_MAINNET_MOCK_HELIOS_RPC_URL,
    override_env_vars=("ETHEREUM_MAINNET_RPC_URL", "BUSINESS_CHAIN_RPC_URL"),
    logger_name="nova-app.chain",
    confirmation_depth=CONFIRMATION_DEPTH,
)


def wait_for_helios(timeout: int = 300):
    """Wait for the business-chain RPC to become reachable for this runtime."""
    return _chain.wait_for_helios(timeout)


def auth_chain_rpc_url() -> str:
    """Preferred auth-chain RPC URL for current runtime mode."""
    return resolve_runtime_url(
        override_env_vars=("NOVA_AUTH_CHAIN_RPC_URL", "AUTH_CHAIN_RPC_URL"),
        enclave_url=AUTH_CHAIN_ENCLAVE_HELIOS_RPC_URL,
        dev_url=AUTH_CHAIN_MOCK_HELIOS_RPC_URL,
    )


def _rpc_source(endpoint: str) -> str:
    if in_enclave():
        return "helios-local"
    if endpoint.startswith("http://odyn.sparsity.cloud:"):
        return "helios-mockup"
    return "external-rpc"


def function_selector(signature: str) -> str:
    """Return 4-byte function selector (0x-prefixed, 8 hex chars)."""
    return "0x" + keccak(signature.encode("utf-8")).hex()[:8]


UPDATE_STATE_SELECTOR = function_selector("updateStateHash(bytes32)")
STATE_HASH_SELECTOR = function_selector("stateHash()")
UPDATE_ETH_PRICE_SELECTOR = function_selector("updateETHPrice(uint256,uint256,uint256)")


def compute_state_hash(data: dict) -> str:
    """Compute keccak256 hash of state data for on-chain anchoring."""
    json_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "0x" + keccak(json_bytes).hex()


def rpc_call_with_failover(method: str, params: list) -> Any:
    """Execute a raw JSON-RPC request through the shared business-chain client."""
    return _chain.make_request(method, params)


def get_business_chain_status() -> Dict[str, Any]:
    status: Dict[str, Any] = {
        "chain_name": BUSINESS_CHAIN_NAME,
        "chain_id": BUSINESS_CHAIN_ID,
        "rpc_url": _chain.endpoint,
        "source": _rpc_source(_chain.endpoint),
        "connected": False,
        "latest_block": None,
    }
    try:
        status["connected"] = bool(_chain.w3.is_connected())
        if status["connected"]:
            status["latest_block"] = _chain.w3.eth.block_number
    except Exception as exc:
        status["error"] = str(exc)
        if _chain.endpoint != ETHEREUM_MAINNET_PUBLIC_RPC_URL:
            status["fallback_rpc_url"] = ETHEREUM_MAINNET_PUBLIC_RPC_URL
            try:
                status["fallback_latest_block"] = fetch_block_number(ETHEREUM_MAINNET_PUBLIC_RPC_URL, timeout=8)
            except Exception as fallback_exc:
                status["fallback_error"] = str(fallback_exc)
    return status


def get_auth_chain_status() -> Dict[str, Any]:
    primary_rpc = auth_chain_rpc_url()
    status: Dict[str, Any] = {
        "chain_name": AUTH_CHAIN_NAME,
        "chain_id": AUTH_CHAIN_ID,
        "rpc_url": primary_rpc,
        "source": _rpc_source(primary_rpc),
        "latest_block": None,
    }
    try:
        status["latest_block"] = fetch_block_number(primary_rpc)
    except Exception as exc:
        status["error"] = str(exc)
        if primary_rpc != AUTH_CHAIN_PUBLIC_RPC_URL:
            status["fallback_rpc_url"] = AUTH_CHAIN_PUBLIC_RPC_URL
            try:
                status["fallback_latest_block"] = fetch_block_number(AUTH_CHAIN_PUBLIC_RPC_URL, timeout=8)
            except Exception as fallback_exc:
                status["fallback_error"] = str(fallback_exc)
    return status


def sign_update_ETH_price(
    *,
    odyn: Any,
    contract_address: str,
    chain_id: int,
    request_id: int,
    price_usd: int,
    updated_at: int,
    broadcast: bool = False,
    sign_tx_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    sender_address: Optional[str] = None,
    signer_kind: str = "tee_wallet",
) -> Dict[str, Any]:
    tx_sender = Web3.to_checksum_address(sender_address or odyn.eth_address())
    contract_address = Web3.to_checksum_address(contract_address)
    w3 = _chain.w3

    nonce = w3.eth.get_transaction_count(tx_sender)
    priority_fee, max_fee = _chain.estimate_fees()

    request_id_encoded = hex(request_id)[2:].zfill(64)
    price_usd_encoded = hex(price_usd)[2:].zfill(64)
    updated_at_encoded = hex(updated_at)[2:].zfill(64)
    data = f"{UPDATE_ETH_PRICE_SELECTOR}{request_id_encoded}{price_usd_encoded}{updated_at_encoded}"

    tx = {
        "kind": "structured",
        "chain_id": hex(chain_id),
        "nonce": hex(nonce),
        "max_priority_fee_per_gas": hex(priority_fee),
        "max_fee_per_gas": hex(max_fee),
        "gas_limit": "0x30D40",
        "to": contract_address,
        "value": "0x0",
        "data": data,
    }

    signed = sign_tx_fn(tx) if sign_tx_fn else odyn.sign_tx(tx)
    signed.setdefault("address", tx_sender)

    return _broadcast_and_verify(
        w3=w3,
        signed=signed,
        broadcast=broadcast,
        tee_address=tx_sender,
        contract_address=contract_address,
        data=data,
        signer_kind=signer_kind,
    )


def sign_update_state_hash(
    *,
    odyn: Any,
    contract_address: str,
    chain_id: int,
    state_hash: str,
    broadcast: bool = False,
    sign_tx_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    sender_address: Optional[str] = None,
    signer_kind: str = "tee_wallet",
) -> Dict[str, Any]:
    """Build, sign and optionally broadcast updateStateHash transaction."""
    tx_sender = Web3.to_checksum_address(sender_address or odyn.eth_address())
    contract_address = Web3.to_checksum_address(contract_address)
    w3 = _chain.w3

    nonce = w3.eth.get_transaction_count(tx_sender)
    priority_fee, max_fee = _chain.estimate_fees()

    clean_hash = state_hash.replace("0x", "").zfill(64)
    data = f"{UPDATE_STATE_SELECTOR}{clean_hash}"

    tx = {
        "kind": "structured",
        "chain_id": hex(chain_id),
        "nonce": hex(nonce),
        "max_priority_fee_per_gas": hex(priority_fee),
        "max_fee_per_gas": hex(max_fee),
        "gas_limit": "0x30D40",
        "to": contract_address,
        "value": "0x0",
        "data": data,
    }

    signed = sign_tx_fn(tx) if sign_tx_fn else odyn.sign_tx(tx)
    signed.setdefault("address", tx_sender)
    return _broadcast_and_verify(
        w3=w3,
        signed=signed,
        broadcast=broadcast,
        tee_address=tx_sender,
        contract_address=contract_address,
        data=data,
        signer_kind=signer_kind,
    )


def _broadcast_and_verify(
    *,
    w3: Web3,
    signed: Dict[str, Any],
    broadcast: bool,
    tee_address: str,
    contract_address: str,
    data: str,
    signer_kind: str = "tee_wallet",
) -> Dict[str, Any]:
    """Helper to broadcast tx and verify execution status with detailed error reporting."""
    result = {
        "raw_transaction": signed.get("raw_transaction"),
        "transaction_hash": signed.get("transaction_hash"),
        "address": signed.get("address"),
        "broadcasted": False,
        "signer_kind": signer_kind,
    }

    if not broadcast:
        return result

    try:
        call_tx = {
            "from": tee_address,
            "to": contract_address,
            "data": data,
            "value": 0,
        }
        try:
            w3.eth.call(call_tx, "latest")
        except ContractLogicError as exc:
            reason = str(exc)
            result["broadcasted"] = False
            result["broadcast_error"] = f"Contract reverted: {reason}"
            logger.error("Pre-flight simulation failed: %s", reason)
            return result
        except Exception as exc:
            result["broadcasted"] = False
            result["broadcast_error"] = f"Simulation error: {exc}"
            logger.error("Pre-flight simulation failed: %s", exc)
            return result

        tx_hash = w3.eth.send_raw_transaction(signed["raw_transaction"])
        result["broadcasted"] = True
        result["rpc_tx_hash"] = tx_hash.hex()
        logger.info("Transaction broadcasted: %s", tx_hash.hex())
    except Exception as exc:
        result["broadcasted"] = False
        result["broadcast_error"] = str(exc)
        logger.error("Broadcast failed: %s", exc)

    return result


def get_onchain_state_hash(*, contract_address: str) -> Optional[str]:
    """Read stateHash() from contract via eth_call."""
    if not contract_address:
        return None
    try:
        result = _chain.eth_call_finalized(contract_address, STATE_HASH_SELECTOR)
        if not result or result in (b"", b"\x00" * 32):
            return None
        return "0x" + result.hex().replace("0x", "").zfill(64)
    except Exception as exc:
        logger.warning("Failed to read on-chain state hash: %s", exc)
        return None
