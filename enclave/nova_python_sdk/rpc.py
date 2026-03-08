"""
Shared blockchain RPC helpers for Nova enclave applications.

Canonical source:
https://github.com/sparsity-xyz/nova-app-template/tree/main/enclave/nova_python_sdk

Updated at:
2026-03-08 10:25:16 CST

SDK version:
0.1.0

Use this module for transport, endpoint selection, and generic JSON-RPC /
Web3 helpers. Keep chain-specific selectors, ABI helpers, and transaction
builders in each app's `chain.py`.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Sequence

import requests
from web3 import Web3

from .env import in_enclave, resolve_runtime_url

DEFAULT_CONFIRMATION_DEPTH = 6


class ChainRpc:
    """
    Minimal Web3-backed RPC helper with Nova-style environment switching.

    Endpoint precedence:
    1. explicit `rpc_url`
    2. first non-empty env var in `override_env_vars`
    3. `enclave_rpc_url` when `IN_ENCLAVE=true`
    4. `dev_rpc_url` otherwise
    """

    def __init__(
        self,
        *,
        enclave_rpc_url: str,
        dev_rpc_url: str,
        rpc_url: Optional[str] = None,
        override_env_vars: Sequence[str] = (),
        logger_name: str = "nova_python_sdk.rpc",
        confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    ):
        self.endpoint = resolve_runtime_url(
            override_url=rpc_url,
            override_env_vars=override_env_vars,
            enclave_url=enclave_rpc_url,
            dev_url=dev_rpc_url,
        )
        self.w3 = Web3(Web3.HTTPProvider(self.endpoint))
        self.logger = logging.getLogger(logger_name)
        self.confirmation_depth = confirmation_depth

    def wait_for_helios(self, timeout: int = 300) -> bool:
        """
        Wait until the configured RPC is reachable and, in enclave mode, synced enough to serve reads.
        """
        is_enclave = in_enclave()
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.w3.is_connected():
                    if not is_enclave:
                        self.logger.info("RPC connected at %s", self.endpoint)
                        return True

                    syncing = self.w3.eth.syncing
                    if not syncing:
                        block = self.w3.eth.block_number
                        if block > 0:
                            self.logger.info("Helios ready at block %s (%s)", block, self.endpoint)
                            return True
                self.logger.info("Waiting for %s RPC...", "Helios" if is_enclave else "development")
            except Exception:
                pass
            time.sleep(5)
        raise TimeoutError(f"RPC failed to connect in time: {self.endpoint}")

    def get_balance(self, address: str) -> int:
        """Return the current wei balance for an address."""
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def get_balance_eth(self, address: str) -> float:
        """Return the current ETH balance for an address."""
        return self.get_balance(address) / 1e18

    def get_nonce(self, address: str) -> int:
        """Return the next transaction nonce for an address."""
        return self.w3.eth.get_transaction_count(Web3.to_checksum_address(address))

    def get_latest_block(self) -> int:
        """Return the latest block number from the configured RPC."""
        return self.w3.eth.block_number

    def estimate_fees(self) -> tuple[int, int]:
        """Return `(max_priority_fee_per_gas, max_fee_per_gas)` for EIP-1559 txs."""
        priority_fee = self.w3.eth.max_priority_fee
        base_fee = self.w3.eth.get_block("latest")["baseFeePerGas"]
        max_fee = (base_fee * 2) + priority_fee
        return priority_fee, max_fee

    def send_raw_transaction(self, signed_hex: str) -> str:
        """Broadcast a signed raw transaction hex string and return its hash."""
        tx_hash = self.w3.eth.send_raw_transaction(signed_hex)
        result = tx_hash.hex()
        return result if result.startswith("0x") else f"0x{result}"

    def eth_call(self, to: str, data: str, block_identifier: Any = "latest") -> bytes:
        """Execute `eth_call` against the configured RPC and return raw bytes."""
        result = self.w3.eth.call(
            {"to": Web3.to_checksum_address(to), "data": data},
            block_identifier=block_identifier,
        )
        return bytes(result)

    def eth_call_finalized(
        self,
        to: str,
        data: str,
        confirmations: Optional[int] = None,
    ) -> bytes:
        """
        Execute a read call against a confirmed block height when possible.
        """
        confirmation_count = self.confirmation_depth if confirmations is None else max(0, int(confirmations))
        try:
            latest_block = self.w3.eth.block_number
            confirmed_block = max(0, latest_block - confirmation_count)
            return self.eth_call(to, data, block_identifier=confirmed_block)
        except Exception as exc:
            self.logger.debug("Finalized eth_call fallback to latest: %s", exc)
            return self.eth_call(to, data, block_identifier="latest")

    def make_request(self, method: str, params: list[Any]) -> Any:
        """Send a raw JSON-RPC request through the configured Web3 provider."""
        return self.w3.provider.make_request(method, params).get("result")


def fetch_block_number(rpc_url: str, timeout: int = 8) -> int:
    """
    Fetch `eth_blockNumber` from an arbitrary JSON-RPC endpoint.
    """
    payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
    response = requests.post(rpc_url, json=payload, timeout=timeout)
    response.raise_for_status()
    data: Dict[str, Any] = response.json()
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    block_hex = data.get("result")
    if not (isinstance(block_hex, str) and block_hex.startswith("0x")):
        raise RuntimeError(f"Invalid eth_blockNumber result: {block_hex}")
    return int(block_hex, 16)
