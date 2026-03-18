"""
Environment helpers shared by the Nova Python SDK.

Canonical source:
https://github.com/sparsity-xyz/nova-app-template/tree/main/enclave/nova_python_sdk

Updated at:
2026-03-08 10:25:16 CST

SDK version:
0.1.0

This module centralizes the template's runtime switching rules:
1. explicit function argument override
2. environment variable overrides
3. enclave-local defaults when `IN_ENCLAVE=true`
4. public mockup defaults for local development
"""

from __future__ import annotations

import os
from typing import Optional, Sequence

DEFAULT_ENCLAVE_CAPSULE-RUNTIME_API = "http://127.0.0.1:18000"
DEFAULT_EXTERNAL_CAPSULE-RUNTIME_API = "http://capsule-runtime.sparsity.cloud:18000"


def in_enclave() -> bool:
    """
    Return whether the app should behave as if it is running inside an enclave.

    This follows the app-level `IN_ENCLAVE` convention used across Nova examples.
    The runtime does not inject this flag automatically for local development;
    set it explicitly when you want enclave-local behavior.
    """
    return os.getenv("IN_ENCLAVE", "false").lower() == "true"


def resolve_runtime_url(
    *,
    override_url: Optional[str] = None,
    override_env_vars: Sequence[str] = (),
    enclave_url: str,
    dev_url: str,
) -> str:
    """
    Resolve a runtime endpoint with explicit override support.

    Precedence:
    1. `override_url`
    2. first non-empty env var in `override_env_vars`
    3. `enclave_url` when `IN_ENCLAVE=true`
    4. `dev_url`
    """
    if override_url:
        return override_url

    for env_var in override_env_vars:
        candidate = os.getenv(env_var, "").strip()
        if candidate:
            return candidate

    return enclave_url if in_enclave() else dev_url


def resolve_capsule-runtime_api_base_url(override_url: Optional[str] = None) -> str:
    """
    Resolve the Capsule-Runtime API base URL.

    Environment overrides checked:
    - `CAPSULE-RUNTIME_API_BASE_URL`
    - `CAPSULE-RUNTIME_ENDPOINT`
    """
    return resolve_runtime_url(
        override_url=override_url,
        override_env_vars=("CAPSULE-RUNTIME_API_BASE_URL", "CAPSULE-RUNTIME_ENDPOINT"),
        enclave_url=DEFAULT_ENCLAVE_CAPSULE-RUNTIME_API,
        dev_url=DEFAULT_EXTERNAL_CAPSULE-RUNTIME_API,
    )
