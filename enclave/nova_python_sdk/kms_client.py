"""
Nova KMS and app-wallet client helpers.

Canonical source:
https://github.com/sparsity-xyz/nova-app-template/tree/main/enclave/nova_python_sdk

Updated at:
2026-03-08 10:25:16 CST

SDK version:
0.1.0

Capsule Capsule API docs:
https://github.com/sparsity-xyz/nova-enclave-capsule/blob/sparsity/docs/internal_api.md

Typical usage inside request handlers:

    from nova_python_sdk.kms_client import NovaKmsClient

    client = NovaKmsClient(endpoint=capsule-runtime.endpoint)
    result = client.kv_get("example-key")

Use this client when you want a thin wrapper around `/v1/kms/*` and
`/v1/app-wallet/*` with explicit HTTP error mapping.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


class PlatformApiError(RuntimeError):
    """
    Raised when the Capsule internal API returns a non-2xx status code.

    Attributes:
        path: Request path that failed.
        status_code: HTTP status code from the upstream service.
        detail: Parsed or raw error detail.
    """

    def __init__(self, path: str, status_code: int, detail: str):
        super().__init__(f"{path} failed with HTTP {status_code}: {detail}")
        self.path = path
        self.status_code = status_code
        self.detail = detail


@dataclass
class NovaKmsClient:
    """
    Thin client for `/v1/kms/*` and `/v1/app-wallet/*`.
    """

    endpoint: str
    timeout_seconds: int = 30

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.endpoint}{path}"
        response: Optional[requests.Response] = None
        try:
            response = requests.request(method=method, url=url, json=payload, timeout=self.timeout_seconds)
            if response.status_code >= 400:
                detail = response.text
                try:
                    detail = json.dumps(response.json(), ensure_ascii=False)
                except Exception:
                    pass
                raise PlatformApiError(path=path, status_code=response.status_code, detail=detail)
            if not response.content:
                return {}
            return response.json()
        except PlatformApiError:
            raise
        except Exception as exc:
            status_code = response.status_code if response is not None else 0
            raise PlatformApiError(path=path, status_code=status_code, detail=str(exc)) from exc

    def derive(self, path: str, context: str = "", length: int = 32) -> Dict[str, Any]:
        """
        Derive a deterministic key from Nova KMS.

        Args:
            path: Logical derivation path.
            context: Optional application-specific context string.
            length: Desired key length in bytes.

        Returns:
            Raw derivation response from Nova KMS.

        Capsule API: `POST /v1/kms/derive`
        """
        return self._request(
            "POST",
            "/v1/kms/derive",
            {"path": path, "context": context, "length": length},
        )

    def kv_get(self, key: str) -> Dict[str, Any]:
        """
        Read a value from the Nova KMS key-value store.

        Args:
            key: Logical KMS KV key.

        Returns:
            Raw KMS KV read response.

        Capsule API: `POST /v1/kms/kv/get`
        """
        return self._request("POST", "/v1/kms/kv/get", {"key": key})

    def kv_put(self, key: str, value: str, ttl_ms: int = 0) -> Dict[str, Any]:
        """
        Write a value into the Nova KMS key-value store.

        Args:
            key: Logical KMS KV key.
            value: Value payload expected by the runtime.
            ttl_ms: Optional time-to-live in milliseconds.

        Returns:
            Raw KMS KV write response.

        Capsule API: `POST /v1/kms/kv/put`
        """
        return self._request(
            "POST",
            "/v1/kms/kv/put",
            {"key": key, "value": value, "ttl_ms": ttl_ms},
        )

    def kv_delete(self, key: str) -> Dict[str, Any]:
        """
        Delete a value from the Nova KMS key-value store.

        Args:
            key: Logical KMS KV key.

        Returns:
            Raw KMS KV delete response.

        Capsule API: `POST /v1/kms/kv/delete`
        """
        return self._request("POST", "/v1/kms/kv/delete", {"key": key})

    def app_wallet_address(self) -> Dict[str, Any]:
        """
        Return the app-wallet Ethereum address.

        Returns:
            Raw app-wallet identity response, including the wallet address.

        Capsule API: `GET /v1/app-wallet/address`
        """
        return self._request("GET", "/v1/app-wallet/address")

    def app_wallet_sign(self, message: str) -> Dict[str, Any]:
        """
        Sign a plaintext message with the app wallet.

        Args:
            message: Plaintext message to sign.

        Returns:
            Raw app-wallet signing response.

        Capsule API: `POST /v1/app-wallet/sign`
        """
        return self._request("POST", "/v1/app-wallet/sign", {"message": message})

    def app_wallet_sign_tx(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a transaction payload with the app wallet.

        Args:
            payload: Either a normalized transaction payload or a dict already
                wrapped as `{"payload": ...}`.

        Returns:
            Raw app-wallet transaction signing response.

        Capsule API: `POST /v1/app-wallet/sign-tx`
        """
        body = dict(payload) if "payload" in payload else {"payload": payload}
        body.setdefault("include_attestation", False)
        return self._request("POST", "/v1/app-wallet/sign-tx", body)
