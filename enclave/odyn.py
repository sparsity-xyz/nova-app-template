"""
=============================================================================
Odyn SDK (odyn.py)
=============================================================================

Platform-provided interface to TEE (Trusted Execution Environment) services.

┌─────────────────────────────────────────────────────────────────────────────┐
│  DO NOT MODIFY THIS FILE                                                    │
│  This is the standard SDK provided by Nova Platform.                        │
└─────────────────────────────────────────────────────────────────────────────┘

Available Methods:
    odyn.eth_address()      → Get TEE's Ethereum address
    odyn.get_random_bytes() → Get 32 bytes from hardware RNG
    odyn.get_attestation()  → Get Nitro attestation document (CBOR)
    odyn.sign_tx(tx)        → Sign an Ethereum transaction
    
    # S3 Storage (via Enclaver internal API)
    odyn.s3_put(key, value) → Store data in S3 storage
    odyn.s3_get(key)        → Retrieve data from S3 storage
    odyn.s3_delete(key)     → Delete data from S3 storage
    odyn.s3_list(prefix)    → List keys in S3 storage

Environment:
    IN_ENCLAVE=true   → Uses localhost:18000 (production TEE)
    IN_ENCLAVE=false  → Uses mock API (development)
"""

import base64
import json
import os
from typing import Dict, Any, Optional, Tuple, List, Union

import requests


class Odyn:
    """
    Wrapper for enclaver's Odyn API.
    
    Automatically detects environment via IN_ENCLAVE env var:
    - IN_ENCLAVE=true  → Production (localhost:18000)
      - IN_ENCLAVE=false → Development (mock API)
    """
    
    # Mock API for local development (when not running in TEE)
    DEFAULT_MOCK_ODYN_API = "http://odyn.sparsity.cloud:18000"
    
    def __init__(self, endpoint: Optional[str] = None):
        """
        Initialize the Odyn helper.
        
        Args:
            endpoint: Override the API endpoint. If None, auto-detects
                      based on IN_ENCLAVE environment variable.
        """
        if endpoint:
            self.endpoint = endpoint
        else:
            # IN_ENCLAVE is set by the Dockerfile/enclaver runtime
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = "http://localhost:18000" if is_enclave else self.DEFAULT_MOCK_ODYN_API

    def _call(self, method: str, path: str, payload: Any = None) -> Any:
        """Internal helper for making API calls."""
        url = f"{self.endpoint}{path}"
        if method.upper() == "POST":
            res = requests.post(url, json=payload, timeout=10)
        else:
            res = requests.get(url, timeout=10)
        res.raise_for_status()
        return res.json()

    # =========================================================================
    # Identity & Signing
    # =========================================================================
    
    def eth_address(self) -> str:
        """
        Get the TEE's Ethereum address.
        
        This address is derived from a hardware-seeded private key
        that never leaves the enclave.
        
        Returns:
            Ethereum address as hex string (e.g., "0x1234...")
        """
        return self._call("GET", "/v1/eth/address")["address"]

    def sign_tx(self, tx: dict) -> dict:
        """
        Sign an Ethereum transaction.
        
        Args:
            tx: Transaction object (to, value, data, nonce, etc.)
            
        Returns:
            Dict with raw_transaction, transaction_hash, signature
        """
        return self._call("POST", "/v1/eth/sign-tx", {"payload": tx})

    def sign_message(self, message: str, include_attestation: bool = False) -> dict:
        """
        Sign a plain-text message using EIP-191 personal message prefix.
        
        Args:
            message: Plain-text message to sign (must be non-empty)
            include_attestation: Whether to include attestation in response
            
        Returns:
            Dict with signature, address, and optionally attestation
        """
        payload = {"message": message, "include_attestation": include_attestation}
        return self._call("POST", "/v1/eth/sign", payload)

    # =========================================================================
    # Randomness & Attestation
    # =========================================================================
    
    def get_random_bytes(self) -> bytes:
        """
        Get 32 random bytes from the hardware RNG (Nitro NSM).
        
        Returns:
            32 bytes of cryptographically secure random data
        """
        res_json = self._call("GET", "/v1/random")
        random_hex = res_json["random_bytes"]
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)

    def get_attestation(self, nonce: Optional[str] = "", user_data: Optional[Union[str, bytes]] = None) -> bytes:
        """
        Get a Nitro attestation document.
        
        The attestation proves this code is running in a genuine
        AWS Nitro Enclave with specific PCR measurements.
        
        Args:
            nonce: Optional base64-encoded nonce to include in attestation
            user_data: Optional user data to embed (bytes or base64-encoded string)
            
        Returns:
            CBOR-encoded attestation document
        """
        url = f"{self.endpoint}/v1/attestation"
        payload: Dict[str, Any] = {"nonce": nonce or ""}
        # Include enclave encryption public key (PEM) for Attestation binding
        try:
            enc_pub = self.get_encryption_public_key()
            if "public_key_pem" in enc_pub:
                payload["public_key"] = enc_pub["public_key_pem"]
        except Exception:
            pass
        if user_data is not None:
            if isinstance(user_data, bytes):
                payload["user_data"] = base64.b64encode(user_data).decode("utf-8")
            else:
                payload["user_data"] = user_data
        res = requests.post(url, json=payload, timeout=10)
        res.raise_for_status()
        return res.content

    # =========================================================================
    # Encryption (ECDH + AES-256-GCM)
    # =========================================================================
    
    def get_encryption_public_key(self) -> dict:
        """
        Get the enclave's P-384 public key for ECDH-based encryption.
        
        Returns:
            Dict with public_key_der (hex) and public_key_pem (PEM format)
        """
        return self._call("GET", "/v1/encryption/public_key")

    def get_encryption_public_key_der(self) -> bytes:
        """Get the encryption public key in DER format (bytes)."""
        pub_data = self.get_encryption_public_key()
        pub_key_hex = pub_data.get("public_key_der", "")
        if pub_key_hex.startswith("0x"):
            pub_key_hex = pub_key_hex[2:]
        return bytes.fromhex(pub_key_hex)

    def encrypt(self, plaintext: str, client_public_key: str) -> dict:
        """
        Encrypt data to send to a client using ECDH + AES-256-GCM.
        
        Args:
            plaintext: String to encrypt
            client_public_key: Hex-encoded DER public key from client
            
        Returns:
            Dict with encrypted_data, enclave_public_key, and nonce
        """
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        payload = {"plaintext": plaintext, "client_public_key": client_public_key}
        return self._call("POST", "/v1/encryption/encrypt", payload)

    def decrypt(self, nonce: str, client_public_key: str, encrypted_data: str) -> str:
        """
        Decrypt data sent from a client using ECDH + AES-256-GCM.
        
        Args:
            nonce: Hex-encoded nonce (at least 12 bytes)
            client_public_key: Hex-encoded DER public key from client
            encrypted_data: Hex-encoded ciphertext with auth tag
            
        Returns:
            Decrypted plaintext string
        """
        # Odyn expects nonce >= 12 bytes; trim if longer
        nonce_hex = nonce[2:] if nonce.startswith("0x") else nonce
        try:
            nonce_bytes = bytes.fromhex(nonce_hex)
            if len(nonce_bytes) > 12:
                nonce_hex = nonce_bytes[:12].hex()
        except Exception:
            nonce_hex = nonce_hex[:24]
        nonce = f"0x{nonce_hex}"
        if not nonce.startswith("0x"):
            nonce = f"0x{nonce}"
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        if not encrypted_data.startswith("0x"):
            encrypted_data = f"0x{encrypted_data}"
        payload = {
            "nonce": nonce,
            "client_public_key": client_public_key,
            "encrypted_data": encrypted_data
        }
        return self._call("POST", "/v1/encryption/decrypt", payload)["plaintext"]

    # =========================================================================
    # S3 Storage (via Enclaver internal API)
    # =========================================================================
    
    def s3_put(self, key: str, value: bytes, content_type: Optional[str] = None) -> bool:
        """
        Store data in S3 storage.
        
        The data is stored under the app's configured S3 prefix.
        Key is automatically scoped to prevent access to other apps' data.
        
        Args:
            key: Storage key (e.g., "state.json", "data/user_123.bin")
            value: Binary data to store
            
        Returns:
            True if successful
        """
        payload = {"key": key, "value": base64.b64encode(value).decode()}
        if content_type:
            payload["content_type"] = content_type
        res = requests.post(f"{self.endpoint}/v1/s3/put", json=payload, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_get(self, key: str) -> Optional[bytes]:
        """
        Retrieve data from S3 storage.
        
        Args:
            key: Storage key to retrieve
            
        Returns:
            Binary data if found, None if key doesn't exist
        """
        res = requests.post(f"{self.endpoint}/v1/s3/get", json={"key": key}, timeout=30)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return base64.b64decode(res.json()["value"])

    def s3_delete(self, key: str) -> bool:
        """
        Delete data from S3 storage.
        
        Args:
            key: Storage key to delete
            
        Returns:
            True if successful
        """
        res = requests.post(f"{self.endpoint}/v1/s3/delete", json={"key": key}, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_list(
        self,
        prefix: Optional[str] = None,
        continuation_token: Optional[str] = None,
        max_keys: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        List keys in S3 storage.
        
        Args:
            prefix: Optional prefix to filter keys (e.g., "data/")
            continuation_token: Token from a previous list response
            max_keys: Optional maximum number of keys to return
            
        Returns:
            Dict with keys, continuation_token, and is_truncated
        """
        payload: Dict[str, Any] = {}
        if prefix is not None:
            payload["prefix"] = prefix
        if continuation_token is not None:
            payload["continuation_token"] = continuation_token
        if max_keys is not None:
            payload["max_keys"] = max_keys
        res = requests.post(f"{self.endpoint}/v1/s3/list", json=payload, timeout=30)
        res.raise_for_status()
        return res.json()


# =============================================================================
# Quick Test (run directly: python odyn.py)
# =============================================================================
if __name__ == "__main__":
    o = Odyn()
    try:
        print(f"Testing Odyn at {o.endpoint}")
        print(f"TEE Address: {o.eth_address()}")
    except Exception as e:
        print(f"Could not connect to Odyn: {e}")


