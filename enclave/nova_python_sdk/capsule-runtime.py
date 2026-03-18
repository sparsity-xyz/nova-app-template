"""
Nova Python SDK wrapper for Capsule-Runtime / Capsule internal APIs.

Canonical source:
https://github.com/sparsity-xyz/nova-app-template/tree/main/enclave/nova_python_sdk

Updated at:
2026-03-08 10:25:16 CST

SDK version:
0.1.0

Capsule Capsule API docs:
https://github.com/sparsity-xyz/capsule/blob/sparsity/docs/internal_api.md

Typical usage inside backend modules under `enclave/`:

    from nova_python_sdk.capsule-runtime import Capsule-Runtime

    capsule-runtime = Capsule-Runtime()
    tee_address = capsule-runtime.eth_address()

`Capsule-Runtime()` resolves its base URL from explicit arguments first, then
`CAPSULE-RUNTIME_API_BASE_URL` / `CAPSULE-RUNTIME_ENDPOINT`, then falls back to
`127.0.0.1:18000` in enclave mode or `capsule-runtime.sparsity.cloud:18000` in local
development.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional

import requests

from .env import resolve_capsule-runtime_api_base_url


class Capsule-Runtime:
    """
    Wrapper around the enclave-local Capsule-Runtime API with Nova development fallbacks.
    """

    def __init__(self, endpoint: Optional[str] = None):
        """
        Initialize the Capsule-Runtime client.

        Args:
            endpoint: Optional explicit base URL override.
        """
        self.endpoint = resolve_capsule-runtime_api_base_url(endpoint)

    def _call(self, method: str, path: str, payload: Any = None) -> Any:
        url = f"{self.endpoint}{path}"
        response = requests.request(method=method.upper(), url=url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()

    def eth_address(self) -> str:
        """
        Return the enclave Ethereum address.

        Returns:
            Hex-encoded Ethereum address.

        Capsule API:
            `GET /v1/eth/address`
        """
        return self._call("GET", "/v1/eth/address")["address"]

    def sign_tx(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign an EIP-1559 transaction payload.

        Args:
            tx: Either a normalized Capsule-Runtime payload or a common Web3-style transaction dict.

        Returns:
            Raw transaction, transaction hash, signature, and signer address.

        Capsule API:
            `POST /v1/eth/sign-tx`
        """
        if "kind" not in tx:
            tx = {
                "kind": "structured",
                "chain_id": hex(tx["chainId"]),
                "nonce": hex(tx["nonce"]),
                "max_priority_fee_per_gas": hex(tx["maxPriorityFeePerGas"]),
                "max_fee_per_gas": hex(tx["maxFeePerGas"]),
                "gas_limit": hex(tx["gas"]),
                "to": tx["to"],
                "value": hex(tx.get("value", 0)),
                "data": tx.get("data", "0x"),
            }
        return self._call("POST", "/v1/eth/sign-tx", {"payload": tx})

    def sign_message(self, message: str, include_attestation: bool = False) -> Dict[str, Any]:
        """
        Sign a plaintext message with EIP-191 personal-sign semantics.

        Args:
            message: Non-empty message string.
            include_attestation: Whether to attach a CBOR attestation in the response.

        Returns:
            Signature response from Capsule-Runtime.

        Capsule API:
            `POST /v1/eth/sign`
        """
        return self._call(
            "POST",
            "/v1/eth/sign",
            {"message": message, "include_attestation": include_attestation},
        )

    def get_random_bytes(self) -> bytes:
        """
        Return 32 bytes of enclave randomness.

        Returns:
            NSM-backed random bytes.

        Capsule API:
            `GET /v1/random`
        """
        response = self._call("GET", "/v1/random")
        random_hex = response["random_bytes"]
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)

    def get_attestation(
        self,
        nonce: str = "",
        user_data: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Return a raw CBOR Nitro attestation document.

        Args:
            nonce: Optional base64-encoded nonce.
            user_data: Optional JSON object to pass as attestation user data.

        Returns:
            Raw CBOR bytes.

        Capsule API:
            `POST /v1/attestation`
        """
        payload: Dict[str, Any] = {"nonce": nonce or ""}
        try:
            encryption_key = self.get_encryption_public_key()
            public_key_pem = encryption_key.get("public_key_pem")
            if public_key_pem:
                payload["public_key"] = public_key_pem
        except Exception:
            pass
        if user_data is not None:
            payload["user_data"] = user_data

        response = requests.post(f"{self.endpoint}/v1/attestation", json=payload, timeout=10)
        response.raise_for_status()
        return response.content

    def get_encryption_public_key(self) -> Dict[str, Any]:
        """
        Return the enclave P-384 encryption public key.

        Returns:
            JSON with DER and PEM encodings.

        Capsule API:
            `GET /v1/encryption/public_key`
        """
        return self._call("GET", "/v1/encryption/public_key")

    def get_encryption_public_key_der(self) -> bytes:
        """
        Return the enclave encryption public key in DER form.

        Returns:
            DER bytes for the enclave P-384 public key.

        Capsule API:
            `GET /v1/encryption/public_key`
        """
        public_key = self.get_encryption_public_key()
        public_key_hex = public_key.get("public_key_der", "")
        if public_key_hex.startswith("0x"):
            public_key_hex = public_key_hex[2:]
        return bytes.fromhex(public_key_hex)

    def encrypt(self, plaintext: str, client_public_key: str) -> Dict[str, Any]:
        """
        Encrypt plaintext for a client using the enclave encryption service.

        Args:
            plaintext: UTF-8 plaintext to encrypt.
            client_public_key: Client DER/SPKI public key as hex.

        Returns:
            Encrypted payload, nonce, and enclave public key.

        Capsule API:
            `POST /v1/encryption/encrypt`
        """
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        return self._call(
            "POST",
            "/v1/encryption/encrypt",
            {"plaintext": plaintext, "client_public_key": client_public_key},
        )

    def decrypt(self, nonce: str, client_public_key: str, encrypted_data: str) -> str:
        """
        Decrypt a client payload with the enclave decryption service.

        Args:
            nonce: AES-GCM nonce as hex.
            client_public_key: Client DER/SPKI public key as hex.
            encrypted_data: Ciphertext+tag as hex.

        Returns:
            UTF-8 plaintext.

        Capsule API:
            `POST /v1/encryption/decrypt`
        """
        nonce_hex = nonce[2:] if nonce.startswith("0x") else nonce
        if not nonce_hex.startswith("0x"):
            nonce_hex = f"0x{nonce_hex}"
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        if not encrypted_data.startswith("0x"):
            encrypted_data = f"0x{encrypted_data}"
        return self._call(
            "POST",
            "/v1/encryption/decrypt",
            {
                "nonce": nonce_hex,
                "client_public_key": client_public_key,
                "encrypted_data": encrypted_data,
            },
        )["plaintext"]

    def s3_put(self, key: str, value: bytes, content_type: Optional[str] = None) -> bool:
        """
        Write binary data to the configured S3 storage backend.

        Args:
            key: Object key to write.
            value: Raw bytes to persist.
            content_type: Optional object content type metadata.

        Returns:
            `True` when the write succeeds.

        Capsule API:
            `POST /v1/s3/put`
        """
        payload = {"key": key, "value": base64.b64encode(value).decode("ascii")}
        if content_type:
            payload["content_type"] = content_type
        response = requests.post(f"{self.endpoint}/v1/s3/put", json=payload, timeout=30)
        response.raise_for_status()
        return response.json().get("success", False)

    def s3_get(self, key: str) -> Optional[bytes]:
        """
        Read binary data from the configured S3 storage backend.

        Args:
            key: Object key to read.

        Returns:
            Raw object bytes, or `None` when the object is not found.

        Capsule API:
            `POST /v1/s3/get`
        """
        response = requests.post(f"{self.endpoint}/v1/s3/get", json={"key": key}, timeout=30)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return base64.b64decode(response.json()["value"])

    def s3_delete(self, key: str) -> bool:
        """
        Delete an object from the configured S3 storage backend.

        Args:
            key: Object key to delete.

        Returns:
            `True` when the delete succeeds.

        Capsule API:
            `POST /v1/s3/delete`
        """
        response = requests.post(f"{self.endpoint}/v1/s3/delete", json={"key": key}, timeout=30)
        response.raise_for_status()
        return response.json().get("success", False)

    def s3_list(
        self,
        prefix: Optional[str] = None,
        continuation_token: Optional[str] = None,
        max_keys: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        List objects from the configured S3 storage backend.

        Args:
            prefix: Optional key prefix filter.
            continuation_token: Optional pagination token from a previous call.
            max_keys: Optional maximum number of keys to return.

        Returns:
            Raw list response from the internal API, including any pagination
            metadata.

        Capsule API:
            `POST /v1/s3/list`
        """
        payload: Dict[str, Any] = {}
        if prefix is not None:
            payload["prefix"] = prefix
        if continuation_token is not None:
            payload["continuation_token"] = continuation_token
        if max_keys is not None:
            payload["max_keys"] = max_keys
        response = requests.post(f"{self.endpoint}/v1/s3/list", json=payload, timeout=30)
        response.raise_for_status()
        return response.json()

    def kms_derive(self, path: str, context: str = "", length: int = 32) -> Dict[str, Any]:
        """
        Derive a deterministic key through Nova KMS.

        Args:
            path: Logical derivation path.
            context: Optional application-specific context string.
            length: Desired key length in bytes.

        Returns:
            Raw derivation response from Nova KMS.

        Capsule API:
            `POST /v1/kms/derive`
        """
        return self._call("POST", "/v1/kms/derive", {"path": path, "context": context, "length": length})

    def kms_kv_get(self, key: str) -> Dict[str, Any]:
        """
        Read a value from Nova KMS key-value storage.

        Args:
            key: Logical KMS KV key.

        Returns:
            Raw KMS KV read response.

        Capsule API:
            `POST /v1/kms/kv/get`
        """
        return self._call("POST", "/v1/kms/kv/get", {"key": key})

    def kms_kv_put(self, key: str, value: str, ttl_ms: int = 0) -> Dict[str, Any]:
        """
        Write a value to Nova KMS key-value storage.

        Args:
            key: Logical KMS KV key.
            value: Value payload expected by the runtime.
            ttl_ms: Optional time-to-live in milliseconds.

        Returns:
            Raw KMS KV write response.

        Capsule API:
            `POST /v1/kms/kv/put`
        """
        return self._call("POST", "/v1/kms/kv/put", {"key": key, "value": value, "ttl_ms": ttl_ms})

    def kms_kv_delete(self, key: str) -> Dict[str, Any]:
        """
        Delete a value from Nova KMS key-value storage.

        Args:
            key: Logical KMS KV key.

        Returns:
            Raw KMS KV delete response.

        Capsule API:
            `POST /v1/kms/kv/delete`
        """
        return self._call("POST", "/v1/kms/kv/delete", {"key": key})

    def app_wallet_address(self) -> Dict[str, Any]:
        """
        Return the app-wallet identity.

        Returns:
            Raw app-wallet identity response, including the wallet address.

        Capsule API:
            `GET /v1/app-wallet/address`
        """
        return self._call("GET", "/v1/app-wallet/address")

    def app_wallet_sign(self, message: str) -> Dict[str, Any]:
        """
        Sign a plaintext message with the app wallet.

        Args:
            message: Plaintext message to sign.

        Returns:
            Raw app-wallet signing response.

        Capsule API:
            `POST /v1/app-wallet/sign`
        """
        return self._call("POST", "/v1/app-wallet/sign", {"message": message})

    def app_wallet_sign_tx(
        self,
        tx: Dict[str, Any],
        include_attestation: bool = False,
    ) -> Dict[str, Any]:
        """
        Sign an EIP-1559 transaction with the app wallet.

        Args:
            tx: Either a normalized payload or a dict already wrapped as
                `{"payload": ...}`.
            include_attestation: Whether to request attestation in the response.

        Returns:
            Raw app-wallet transaction signing response.

        Capsule API:
            `POST /v1/app-wallet/sign-tx`
        """
        payload = dict(tx) if "payload" in tx else {"payload": tx}
        payload.setdefault("include_attestation", include_attestation)
        return self._call("POST", "/v1/app-wallet/sign-tx", payload)
