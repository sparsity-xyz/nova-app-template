from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional

import requests
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_hash.auto import keccak

from config import (
    AUTH_CHAIN_ID,
    AUTH_CHAIN_LOCAL_RPC_URL,
    AUTH_CHAIN_NAME,
    AUTH_CHAIN_RPC_URL,
    BUSINESS_CHAIN_DIRECT_RPC_URL,
    BUSINESS_CHAIN_ID,
    BUSINESS_CHAIN_LOCAL_RPC_URL,
    BUSINESS_CHAIN_NAME,
)

logger = logging.getLogger("nova-app.chain")

# Minimum confirmations for reorg-resistant read calls.
CONFIRMATION_DEPTH: int = 6

class Chain:
    """Helper for interacting with the blockchain via Helios RPC."""

    DEFAULT_HELIOS_RPC = BUSINESS_CHAIN_LOCAL_RPC_URL

    def __init__(self, rpc_url: Optional[str] = None):
        if rpc_url:
            self.endpoint = rpc_url
        else:
            if _in_enclave():
                # In enclave: use local trustless Helios endpoint for the business chain.
                self.endpoint = self.DEFAULT_HELIOS_RPC
            else:
                # Outside enclave: default to Ethereum mainnet public RPC.
                self.endpoint = BUSINESS_CHAIN_DIRECT_RPC_URL
            
        self.w3 = Web3(Web3.HTTPProvider(self.endpoint))

    def wait_for_helios(self, timeout: int = 300):
        """Wait for RPC to be ready."""
        is_enclave = _in_enclave()
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.w3.is_connected():
                    if not is_enclave:
                        logger.info("Business RPC connected")
                        return True
                        
                    # Helios-specific sync check
                    syncing = self.w3.eth.syncing
                    if not syncing:
                        block = self.w3.eth.block_number
                        if block > 0:
                            logger.info(f"Business-chain Helios ready at block {block} ({self.endpoint})")
                            return True
                logger.info(f"Waiting for {'Helios' if is_enclave else 'business'} RPC...")
            except Exception:
                pass
            time.sleep(5)
        raise TimeoutError(f"{'Helios' if is_enclave else 'business'} RPC failed to connect in time")

    def get_balance(self, address: str) -> int:
        """Get balance in wei."""
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def get_balance_eth(self, address: str) -> float:
        """Get balance in ETH (convenience method)."""
        balance_wei = self.get_balance(address)
        return balance_wei / 1e18

    def get_nonce(self, address: str) -> int:
        return self.w3.eth.get_transaction_count(Web3.to_checksum_address(address))

    def get_latest_block(self) -> int:
        return self.w3.eth.block_number

    def estimate_fees(self):
        """Estimate EIP-1559 fees."""
        priority_fee = self.w3.eth.max_priority_fee
        base_fee = self.w3.eth.get_block('latest')['baseFeePerGas']
        max_fee = (base_fee * 2) + priority_fee
        return priority_fee, max_fee

    def send_raw_transaction(self, signed_hex: str) -> str:
        tx_hash = self.w3.eth.send_raw_transaction(signed_hex)
        res = tx_hash.hex()
        return res if res.startswith("0x") else f"0x{res}"

    def eth_call(self, to: str, data: str, block_identifier: Any = "latest") -> bytes:
        result = self.w3.eth.call(
            {"to": Web3.to_checksum_address(to), "data": data},
            block_identifier=block_identifier,
        )
        return bytes(result)

    def eth_call_finalized(self, to: str, data: str, confirmations: int = CONFIRMATION_DEPTH) -> bytes:
        """
        Reorg-resistant read call using a confirmed block height.
        Falls back to latest if confirmed block call is unavailable.
        """
        try:
            latest_block = self.w3.eth.block_number
            confirmed_block = max(0, latest_block - max(0, int(confirmations)))
            return self.eth_call(to, data, block_identifier=confirmed_block)
        except Exception as exc:
            logger.debug(f"Finalized eth_call fallback to latest: {exc}")
            return self.eth_call(to, data, block_identifier="latest")

def _in_enclave() -> bool:
    return os.getenv("IN_ENCLAVE", "False").lower() == "true"

# Default chain instance
_chain = Chain()

def wait_for_helios(timeout: int = 300):
    return _chain.wait_for_helios(timeout)





def auth_chain_rpc_url() -> str:
    """Preferred auth-chain RPC URL for current runtime mode."""
    return AUTH_CHAIN_LOCAL_RPC_URL if _in_enclave() else AUTH_CHAIN_RPC_URL


def _eth_block_number(rpc_url: str, timeout: int = 8) -> int:
    payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
    response = requests.post(rpc_url, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    block_hex = data.get("result")
    if not (isinstance(block_hex, str) and block_hex.startswith("0x")):
        raise RuntimeError(f"Invalid eth_blockNumber result: {block_hex}")
    return int(block_hex, 16)

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

def _rpc_call(rpc_url: str, method: str, params: list) -> Any:
    """Helper for direct RPC calls (uses the Chain instance's w3)."""
    # Note: rpc_url is mostly ignored now in favor of the w3 provider
    # but we can use it to create a temporary provider if needed.
    if rpc_url and rpc_url != _chain.endpoint:
        temp_w3 = Web3(Web3.HTTPProvider(rpc_url))
        return temp_w3.provider.make_request(method, params).get("result")
    return _chain.w3.provider.make_request(method, params).get("result")

def rpc_call_with_failover(method: str, params: list) -> Any:
    return _rpc_call("", method, params)


def get_business_chain_status() -> Dict[str, Any]:
    status: Dict[str, Any] = {
        "chain_name": BUSINESS_CHAIN_NAME,
        "chain_id": BUSINESS_CHAIN_ID,
        "rpc_url": _chain.endpoint,
        "source": "helios-local" if _in_enclave() else "external-rpc",
        "connected": False,
        "latest_block": None,
    }
    try:
        status["connected"] = bool(_chain.w3.is_connected())
        if status["connected"]:
            status["latest_block"] = _chain.w3.eth.block_number
    except Exception as exc:
        status["error"] = str(exc)
    return status


def get_auth_chain_status() -> Dict[str, Any]:
    primary_rpc = auth_chain_rpc_url()
    status: Dict[str, Any] = {
        "chain_name": AUTH_CHAIN_NAME,
        "chain_id": AUTH_CHAIN_ID,
        "rpc_url": primary_rpc,
        "source": "helios-local" if _in_enclave() else "external-rpc",
        "latest_block": None,
    }
    try:
        status["latest_block"] = _eth_block_number(primary_rpc)
    except Exception as exc:
        status["error"] = str(exc)
        # In enclave mode, local auth-chain Helios is preferred.
        # If local endpoint is unavailable, provide external RPC visibility.
        if _in_enclave() and primary_rpc != AUTH_CHAIN_RPC_URL:
            status["fallback_rpc_url"] = AUTH_CHAIN_RPC_URL
            try:
                status["fallback_latest_block"] = _eth_block_number(AUTH_CHAIN_RPC_URL, timeout=8)
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

    # ABI encode
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
        "gas_limit": "0x30D40", # 200k fallback
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
        "gas_limit": "0x30D40", # 200k fallback
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
        # Pre-flight simulation: catch revert errors before broadcasting
        call_tx = {
            "from": tee_address,
            "to": contract_address,
            "data": data,
            "value": 0
        }
        try:
            w3.eth.call(call_tx, "latest")
        except ContractLogicError as cle:
            # ContractLogicError contains the revert reason
            reason = str(cle)
            result["broadcasted"] = False
            result["broadcast_error"] = f"Contract reverted: {reason}"
            logger.error(f"Pre-flight simulation failed: {reason}")
            return result
        except Exception as sim_e:
            # Other errors (network, etc.)
            result["broadcasted"] = False
            result["broadcast_error"] = f"Simulation error: {sim_e}"
            logger.error(f"Pre-flight simulation failed: {sim_e}")
            return result

        # Simulation passed - safe to broadcast
        tx_hash = w3.eth.send_raw_transaction(signed["raw_transaction"])
        result["broadcasted"] = True
        result["rpc_tx_hash"] = tx_hash.hex()
        logger.info(f"Transaction broadcasted: {tx_hash.hex()}")
    except Exception as e:
        result["broadcasted"] = False
        result["broadcast_error"] = str(e)
        logger.error(f"Broadcast failed: {e}")

    return result

def get_onchain_state_hash(*, contract_address: str) -> Optional[str]:
    """Read stateHash() from contract via eth_call."""
    if not contract_address:
        return None
    try:
        result = _chain.eth_call_finalized(contract_address, STATE_HASH_SELECTOR)
        if not result or result in (b'', b'\x00'*32):
            return None
        return "0x" + result.hex().replace("0x", "").zfill(64)
    except Exception as e:
        logger.warning(f"Failed to read on-chain state hash: {e}")
        return None
