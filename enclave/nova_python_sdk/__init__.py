"""
Canonical Python SDK for Nova enclave applications.

Source repository:
https://github.com/sparsity-xyz/nova-app-template

Capsule Capsule API docs:
https://github.com/sparsity-xyz/nova-enclave-capsule/blob/sparsity/docs/internal_api.md

This package lives under `enclave/nova_python_sdk/`, so backend modules inside
`enclave/` can import it directly:

    from nova_python_sdk.capsule-runtime import Capsule-Runtime
    from nova_python_sdk.kms_client import NovaKmsClient
    from nova_python_sdk.rpc import ChainRpc
"""

from .kms_client import NovaKmsClient, PlatformApiError
from .capsule-runtime import Capsule-Runtime
from .rpc import ChainRpc, fetch_block_number
from .version import SDK_VERSION

__all__ = [
    "ChainRpc",
    "NovaKmsClient",
    "Capsule-Runtime",
    "PlatformApiError",
    "SDK_VERSION",
    "fetch_block_number",
]
