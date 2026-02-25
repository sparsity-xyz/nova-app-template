from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


class PlatformApiError(RuntimeError):
    def __init__(self, path: str, status_code: int, detail: str):
        super().__init__(f"{path} failed with HTTP {status_code}: {detail}")
        self.path = path
        self.status_code = status_code
        self.detail = detail


@dataclass
class NovaKmsClient:
    endpoint: str
    timeout_seconds: int = 30

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.endpoint}{path}"
        response: Optional[requests.Response] = None
        try:
            response = requests.request(method=method, url=url, json=payload, timeout=self.timeout_seconds)
            if response.status_code >= 400:
                detail = response.text
                try:
                    parsed = response.json()
                    detail = json.dumps(parsed, ensure_ascii=False)
                except Exception:
                    pass
                raise PlatformApiError(path=path, status_code=response.status_code, detail=detail)
            if not response.content:
                return {}
            return response.json()
        except PlatformApiError:
            raise
        except Exception as exc:
            status = response.status_code if response is not None else 0
            raise PlatformApiError(path=path, status_code=status, detail=str(exc)) from exc

    def derive(self, path: str, context: str = "", length: int = 32) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/kms/derive",
            {"path": path, "context": context, "length": length},
        )

    def kv_get(self, key: str) -> Dict[str, Any]:
        return self._request("POST", "/v1/kms/kv/get", {"key": key})

    def kv_put(self, key: str, value: str, ttl_ms: int = 0) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v1/kms/kv/put",
            {"key": key, "value": value, "ttl_ms": ttl_ms},
        )

    def kv_delete(self, key: str) -> Dict[str, Any]:
        return self._request("POST", "/v1/kms/kv/delete", {"key": key})

    def app_wallet_address(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/app-wallet/address")

    def app_wallet_sign(self, message: str) -> Dict[str, Any]:
        return self._request("POST", "/v1/app-wallet/sign", {"message": message})



    def app_wallet_sign_tx(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body: Dict[str, Any]
        if "payload" in payload:
            body = dict(payload)
        else:
            body = {"payload": payload}
        body.setdefault("include_attestation", False)
        return self._request("POST", "/v1/app-wallet/sign-tx", body)
