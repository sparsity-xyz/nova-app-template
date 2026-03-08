"""
Canonical Python SDK for Nova enclave applications.

Source repository:
https://github.com/sparsity-xyz/nova-app-template

Enclaver Internal API docs:
https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api.md

This package lives under `enclave/nova_python_sdk/`, so backend modules inside
`enclave/` can import it directly:

    from nova_python_sdk.odyn import Odyn
    from nova_python_sdk.kms_client import NovaKmsClient
    from nova_python_sdk.rpc import ChainRpc
"""

from .kms_client import NovaKmsClient, PlatformApiError
from .odyn import Odyn
from .rpc import ChainRpc, fetch_block_number
from .version import SDK_VERSION

__all__ = [
    "ChainRpc",
    "NovaKmsClient",
    "Odyn",
    "PlatformApiError",
    "SDK_VERSION",
    "fetch_block_number",
]
