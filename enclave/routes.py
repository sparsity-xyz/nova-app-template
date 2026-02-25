"""
=============================================================================
User Routes (routes.py)
=============================================================================

Define your custom API endpoints here.

┌─────────────────────────────────────────────────────────────────────────────┐
│  MODIFY THIS FILE                                                           │
│  Add your own API endpoints and business logic here.                        │
└─────────────────────────────────────────────────────────────────────────────┘

How it works:
    - All routes are prefixed with /api (e.g., /api/echo)
    - You can access app_state and odyn after init() is called
    - Use FastAPI's standard decorators (@router.get, @router.post, etc.)

Demo endpoints included:
    - POST /api/echo       → Echo back a message with TEE address
    - GET  /api/info       → Get app info and state keys
    - GET  /api/random     → Generate random bytes using NSM hardware RNG
    - POST /api/storage    → Save key-value data to S3 storage
    - GET  /api/storage    → Load key-value data from S3 storage
    - GET  /api/contract   → Read contract state (stateHash)
    - POST /api/contract/update-state → Write to contract (updateStateHash)
    - POST /api/oracle/update-now     → Fetch ETH/USD and update on-chain price
    - GET  /api/events/oracle         → Fetch oracle-related on-chain events
"""

import json
import logging
import base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING, Callable, Tuple

import requests
from web3 import Web3
from eth_hash.auto import keccak
from fastapi import APIRouter, HTTPException, Body, Response
from pydantic import BaseModel

from chain import compute_state_hash, sign_update_state_hash, get_onchain_state_hash
from chain import (
    sign_update_ETH_price,
    rpc_call_with_failover,
    auth_chain_rpc_url,
    get_business_chain_status,
    get_auth_chain_status,
    _chain,
)
from config import (
    ANCHOR_ON_WRITE,
    AUTH_CHAIN_ID,
    BUSINESS_CHAIN_ID,
    BUSINESS_CHAIN_NAME,
    CONTRACT_ADDRESS,
    BROADCAST_TX,
    AUTH_CHAIN_LOCAL_RPC_URL,
    BUSINESS_CHAIN_LOCAL_RPC_URL,
    S3_ENCRYPTION_MODE,
    S3_ENCRYPTION_KEY_SCOPE,
    S3_ENCRYPTION_AAD_MODE,
    S3_ENCRYPTION_KEY_VERSION,
    S3_ENCRYPTION_ACCEPT_PLAINTEXT,
)
from kms_client import NovaKmsClient, PlatformApiError

# Type hint for Odyn (actual import would cause circular dependency)
if TYPE_CHECKING:
    from odyn import Odyn

logger = logging.getLogger("nova-app.routes")

# =============================================================================
# Shared References (set by app.py during startup)
# =============================================================================
app_state: Optional[dict] = None
odyn: Optional["Odyn"] = None
kms_client: Optional[NovaKmsClient] = None


def init(state_ref: dict, odyn_ref: "Odyn"):
    """
    Initialize the routes module with shared references.
    
    Called by app.py during startup. Do not call directly.
    
    Args:
        state_ref: Reference to app_state dict
        odyn_ref: Reference to Odyn instance
    """
    global app_state, odyn, kms_client
    app_state = state_ref
    odyn = odyn_ref
    kms_client = NovaKmsClient(endpoint=odyn_ref.endpoint)
    logger.info("Routes module initialized")


def _require_kms_client() -> NovaKmsClient:
    if not kms_client:
        raise HTTPException(status_code=500, detail="KMS client not initialized")
    return kms_client


def _raise_platform_error(err: PlatformApiError) -> None:
    # Keep user-actionable statuses intact; map transient upstream failures to 502.
    passthrough = {400, 401, 403, 404}
    status_code = err.status_code if err.status_code in passthrough else 502
    raise HTTPException(
        status_code=status_code,
        detail={
            "path": err.path,
            "status_code": err.status_code,
            "message": err.detail,
        },
    )


def _resolve_tx_signer() -> Tuple[str, str, Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """
    Prefer app-wallet signer for business txs; gracefully fall back to TEE wallet signer.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")

    tee_wallet_address = Web3.to_checksum_address(odyn.eth_address())

    try:
        client = _require_kms_client()
        app_wallet_info = client.app_wallet_address()
        app_wallet_address = Web3.to_checksum_address(app_wallet_info["address"])

        def _app_wallet_signer(tx: Dict[str, Any]) -> Dict[str, Any]:
            return client.app_wallet_sign_tx({"payload": tx, "include_attestation": False})

        return "app_wallet", app_wallet_address, _app_wallet_signer
    except Exception as exc:
        logger.warning("App-wallet signer unavailable, using TEE signer: %s", exc)

    def _tee_signer(tx: Dict[str, Any]) -> Dict[str, Any]:
        return odyn.sign_tx(tx)

    return "tee_wallet", tee_wallet_address, _tee_signer


# =============================================================================
# Router Configuration
# =============================================================================
router = APIRouter(prefix="/api", tags=["user"])
public_router = APIRouter(tags=["public"])


# =============================================================================
# Request/Response Models
# =============================================================================
class EchoRequest(BaseModel):
    message: str

class EchoResponse(BaseModel):
    reply: str
    tee_address: Optional[str] = None

class StorageRequest(BaseModel):
    key: str
    value: Any
    content_type: Optional[str] = None

class ContractWriteRequest(BaseModel):
    """Request to update state hash on contract."""
    state_hash: str  # bytes32 as hex string

class SignMessageRequest(BaseModel):
    """Request to sign a message."""
    message: str
    include_attestation: bool = False

class EncryptRequest(BaseModel):
    """Request to encrypt data for client."""
    plaintext: str
    client_public_key: str  # Hex-encoded DER public key

class DecryptRequest(BaseModel):
    """Request to decrypt data from client."""
    nonce: str
    client_public_key: str
    encrypted_data: str

class EncryptedPayload(BaseModel):
    nonce: str
    public_key: str
    data: str


class KmsDeriveRequest(BaseModel):
    path: str
    context: str = ""
    length: int = 32


class KmsKvGetRequest(BaseModel):
    key: str


class KmsKvPutRequest(BaseModel):
    key: str
    value: str
    ttl_ms: int = 0


class KmsKvDeleteRequest(BaseModel):
    key: str


class AppWalletSignRequest(BaseModel):
    message: str





# =============================================================================
# TEE Identity & Cryptography Endpoints
# =============================================================================

@router.get("/attestation")
def get_attestation(nonce: str = ""):
    """
    Get a Nitro attestation document.
    
    The attestation proves this code is running in a genuine
    AWS Nitro Enclave with specific PCR measurements.
    
    Returns: CBOR-encoded attestation document (base64)
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        attestation = odyn.get_attestation(nonce)
        return {"attestation": base64.b64encode(attestation).decode()}
    except Exception as e:
        logger.error(f"Failed to get attestation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@public_router.post("/.well-known/attestation")
def well_known_attestation(body: Dict[str, Any] = Body(default_factory=dict)):
    """
    Public Attestation endpoint for frontend attestation fetch.

    Returns raw CBOR attestation document.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")

    try:
        nonce = body.get("nonce", "") if isinstance(body, dict) else ""
        attestation = odyn.get_attestation(nonce)
        return Response(content=attestation, media_type="application/cbor")
    except Exception as e:
        logger.error(f"Failed to get attestation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sign")
def sign_message(req: SignMessageRequest):
    """
    Sign a message using EIP-191 personal message prefix.
    
    The signature proves the message was signed by the TEE's
    hardware-seeded private key.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        result = odyn.sign_message(req.message, req.include_attestation)
        return result
    except Exception as e:
        logger.error(f"Failed to sign message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/encryption/public_key")
def get_encryption_public_key():
    """
    Get the enclave's P-384 public key for ECDH-based encryption.
    
    Use this to establish an encrypted channel with the TEE.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        return odyn.get_encryption_public_key()
    except Exception as e:
        logger.error(f"Failed to get encryption public key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/encrypt")
def encrypt_data(req: EncryptRequest):
    """
    Encrypt data to send to a client using ECDH + AES-256-GCM.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        return odyn.encrypt(req.plaintext, req.client_public_key)
    except Exception as e:
        logger.error(f"Failed to encrypt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decrypt")
def decrypt_data(req: DecryptRequest):
    """
    Decrypt data sent from a client using ECDH + AES-256-GCM.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        plaintext = odyn.decrypt(req.nonce, req.client_public_key, req.encrypted_data)
        return {"plaintext": plaintext}
    except Exception as e:
        logger.error(f"Failed to decrypt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Demo Endpoints
# =============================================================================

@router.post("/echo")
def echo_example(payload: Dict[str, Any] = Body(...)):
    """Echo back a message with TEE address (supports encrypted payloads)."""
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")

    try:
        address = Web3.to_checksum_address(odyn.eth_address())
    except Exception:
        address = "unavailable"

    # Encrypted flow: {nonce, public_key, data}
    if {"nonce", "public_key", "data"}.issubset(payload.keys()):
        enc = EncryptedPayload(**payload)
        try:
            plaintext = odyn.decrypt(enc.nonce, enc.public_key, enc.data)
            req = EchoRequest(**json.loads(plaintext))
            response = {"reply": f"Echo: {req.message}", "tee_address": address}
            encrypted = odyn.encrypt(json.dumps(response), enc.public_key)
            return {
                "data": {
                    "encrypted_data": encrypted.get("encrypted_data"),
                    "nonce": encrypted.get("nonce"),
                    "public_key": encrypted.get("enclave_public_key"),
                }
            }
        except requests.exceptions.HTTPError as e:
            detail = None
            try:
                detail = e.response.text if e.response is not None else None
            except Exception:
                detail = None
            raise HTTPException(
                status_code=400,
                detail=f"Odyn encryption/decryption failed: {detail or str(e)}",
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Encrypted request failed: {str(e)}")

    # Plaintext flow
    req = EchoRequest(**payload)
    return EchoResponse(reply=f"Echo: {req.message}", tee_address=address)


@router.get("/info")
def get_info():
    """Get app info and current state keys."""
    return {
        "app": "Nova App Template",
        "state_keys": list(app_state.get("data", {}).keys()) if app_state else []
    }


# =============================================================================
# NSM Random Demo
# =============================================================================

@router.get("/random")
def get_random():
    """
    Generate random bytes using NSM hardware RNG.
    
    In production (Nitro Enclave), this uses the hardware random number generator.
    In development, it falls back to software RNG.
    
    Returns:
        random_hex: 32 random bytes as hex string
        random_int: Random integer (0 to 2^256-1)
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        random_bytes = odyn.get_random_bytes()
        random_hex = random_bytes.hex()
        random_int = int.from_bytes(random_bytes, 'big')
        
        return {
            "random_hex": f"0x{random_hex}",
            "random_int": str(random_int),
            "bytes_length": len(random_bytes)
        }
    except Exception as e:
        logger.error(f"Failed to get random bytes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Multi-Chain + KMS/App-Wallet Endpoints
# =============================================================================

@router.get("/chains")
def get_chain_status():
    """
    Return chain topology used by the template:
    - auth chain: registry/KMS authorization
    - business chain: app logic + contract writes (Ethereum mainnet default)
    """
    business = get_business_chain_status()
    auth = get_auth_chain_status()
    return {
        "auth_chain": auth,
        "business_chain": business,
        "multi_chain_enabled": True,
        "auth_chain_local_rpc_url": AUTH_CHAIN_LOCAL_RPC_URL,
        "business_chain_local_rpc_url": BUSINESS_CHAIN_LOCAL_RPC_URL,
        "auth_chain_active_rpc_url": auth_chain_rpc_url(),
        "business_chain_active_rpc_url": _chain.endpoint,
        "business_chain_name": BUSINESS_CHAIN_NAME,
    }


@router.get("/storage/config")
def get_storage_config():
    """
    Surface storage encryption expectations for quick diagnostics.
    """
    return {
        "s3_encryption_mode": S3_ENCRYPTION_MODE,
        "kms_required": S3_ENCRYPTION_MODE == "kms",
        "key_scope": S3_ENCRYPTION_KEY_SCOPE,
        "aad_mode": S3_ENCRYPTION_AAD_MODE,
        "key_version": S3_ENCRYPTION_KEY_VERSION,
        "accept_plaintext": S3_ENCRYPTION_ACCEPT_PLAINTEXT,
        "anchor_on_write": ANCHOR_ON_WRITE,
    }


@router.get("/enclaver/features")
def get_enclaver_feature_snapshot():
    """
    Snapshot for the four core enclaver capabilities used by this template:
    1) multi-chain auth/business routing
    2) S3 encryption configuration
    3) app-wallet availability
    4) KMS derive + KV endpoint availability
    """
    chain_status = get_chain_status()
    storage_status = get_storage_config()

    app_wallet: Dict[str, Any] = {
        "enabled": False,
        "address": None,
        "error": None,
    }
    kms: Dict[str, Any] = {
        "enabled": False,
        "probe": None,
        "error": None,
    }

    try:
        client = _require_kms_client()

        # App wallet probe
        try:
            addr_res = client.app_wallet_address()
            app_wallet["enabled"] = True
            app_wallet["address"] = addr_res.get("address")
            app_wallet["raw"] = addr_res
        except Exception as app_exc:
            app_wallet["error"] = str(app_exc)

        # KMS probe (non-persistent derive call)
        try:
            derive_res = client.derive(
                path="app/template/enclaver-feature-probe",
                context="snapshot",
                length=16,
            )
            kms["enabled"] = True
            kms["probe"] = {
                "path": "app/template/enclaver-feature-probe",
                "length": 16,
                "result": derive_res,
            }
        except Exception as kms_exc:
            kms["error"] = str(kms_exc)
    except Exception as exc:
        app_wallet["error"] = str(exc)
        kms["error"] = str(exc)

    return {
        "features": {
            "multiple_chain_support": chain_status,
            "s3_encryption_support": storage_status,
            "app_wallet_support": app_wallet,
            "kms_support": kms,
        }
    }


@router.post("/kms/derive")
def kms_derive(req: KmsDeriveRequest):
    client = _require_kms_client()
    try:
        return client.derive(path=req.path, context=req.context, length=req.length)
    except PlatformApiError as err:
        _raise_platform_error(err)


@router.post("/kms/kv/get")
def kms_kv_get(req: KmsKvGetRequest):
    client = _require_kms_client()
    try:
        return client.kv_get(key=req.key)
    except PlatformApiError as err:
        _raise_platform_error(err)


@router.post("/kms/kv/put")
def kms_kv_put(req: KmsKvPutRequest):
    client = _require_kms_client()
    try:
        return client.kv_put(key=req.key, value=req.value, ttl_ms=req.ttl_ms)
    except PlatformApiError as err:
        _raise_platform_error(err)


@router.post("/kms/kv/delete")
def kms_kv_delete(req: KmsKvDeleteRequest):
    client = _require_kms_client()
    try:
        return client.kv_delete(key=req.key)
    except PlatformApiError as err:
        _raise_platform_error(err)


@router.get("/app-wallet/address")
def app_wallet_address():
    client = _require_kms_client()
    try:
        return client.app_wallet_address()
    except PlatformApiError as err:
        _raise_platform_error(err)


@router.post("/app-wallet/sign")
def app_wallet_sign(req: AppWalletSignRequest):
    client = _require_kms_client()
    try:
        return client.app_wallet_sign(message=req.message)
    except PlatformApiError as err:
        _raise_platform_error(err)





@router.post("/app-wallet/sign-tx")
def app_wallet_sign_tx(payload: Dict[str, Any] = Body(...)):
    client = _require_kms_client()
    try:
        return client.app_wallet_sign_tx(payload=payload)
    except PlatformApiError as err:
        _raise_platform_error(err)


# =============================================================================
# S3 Storage Demo
# =============================================================================

@router.post("/storage")
def save_to_storage(req: StorageRequest):
    """
    Save key-value data to S3 storage.
    
    Data is stored under the app's S3 prefix (isolated per app).
    The value can be any JSON-serializable data.
    
    Example:
        POST /api/storage
        {"key": "user_prefs", "value": {"theme": "dark", "lang": "en"}}
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        # Normalize value: if it's a string that looks like JSON, parse it first
        store_value = req.value
        if isinstance(req.value, str):
            try:
                store_value = json.loads(req.value)
            except (json.JSONDecodeError, TypeError):
                pass  # Keep as string if not valid JSON

        # Serialize value to JSON bytes
        json_bytes = json.dumps(store_value).encode('utf-8')
        
        # Save to S3
        success = odyn.s3_put(req.key, json_bytes, content_type=req.content_type)
        
        # Also update in-memory state
        if app_state:
            app_state["data"][req.key] = store_value
        
        result: Dict[str, Any] = {
            "success": success,
            "key": req.key,
            "message": "Data saved to S3 storage",
            "s3_encryption_mode": S3_ENCRYPTION_MODE,
        }

        # Anchor state hash on-chain for user_settings key when enabled.
        if success and ANCHOR_ON_WRITE and req.key == "user_settings":
            anchor_status: Dict[str, Any] = {}

            if not CONTRACT_ADDRESS:
                anchor_status["anchor_skipped"] = True
                anchor_status["anchor_note"] = "App contract not configured (CONTRACT_ADDRESS is empty)"
            else:
                # Resolve tx signer (app wallet preferred, tee wallet fallback).
                try:
                    signer_kind, signer_address, sign_tx_fn = _resolve_tx_signer()
                    tee_address = Web3.to_checksum_address(odyn.eth_address())
                    anchor_status["tee_address"] = tee_address
                    anchor_status["tx_signer"] = signer_kind
                    anchor_status["signer_address"] = signer_address
                except Exception as e:
                    anchor_status["anchor_error"] = f"Failed to resolve transaction signer: {e}"
                    anchor_status["error_type"] = "tx_signer_unavailable"
                    result.update(anchor_status)
                    return result

                # Check signer balance for gas.
                try:
                    from chain import _chain
                    balance_eth = _chain.get_balance_eth(signer_address)
                    anchor_status["signer_balance_eth"] = balance_eth
                    if signer_kind == "tee_wallet":
                        anchor_status["tee_balance_eth"] = balance_eth
                    if balance_eth == 0:
                        anchor_status["anchor_error"] = (
                            f"{signer_kind} signer {signer_address} has no funds. "
                            "Please fund the signer to cover gas."
                        )
                        anchor_status["error_type"] = "tx_signer_no_funds"
                        result.update(anchor_status)
                        return result
                except Exception as e:
                    logger.warning(f"Failed to check signer balance: {e}")
                    anchor_status["balance_check_error"] = str(e)

                # Compute state hash (use normalized store_value, not raw req.value)
                state_hash = compute_state_hash(store_value)
                anchor_status["state_hash"] = state_hash
                anchor_status["contract_address"] = CONTRACT_ADDRESS

                # Sign and broadcast
                try:
                    anchor = sign_update_state_hash(
                        odyn=odyn,
                        contract_address=CONTRACT_ADDRESS,
                        chain_id=BUSINESS_CHAIN_ID,
                        state_hash=state_hash,
                        broadcast=BROADCAST_TX,
                        sign_tx_fn=sign_tx_fn,
                        sender_address=signer_address,
                        signer_kind=signer_kind,
                    )
                    anchor_status["anchor_tx"] = anchor
                    anchor_status["broadcast"] = BROADCAST_TX

                    # Check broadcast result
                    if BROADCAST_TX and anchor.get("broadcasted") is False:
                        anchor_status["anchor_error"] = anchor.get("broadcast_error", "Unknown broadcast error")
                        anchor_status["error_type"] = "broadcast_failed"
                except Exception as e:
                    error_str = str(e).lower()
                    anchor_status["anchor_error"] = str(e)
                    if "insufficient funds" in error_str or "doesn't have enough funds" in error_str:
                        anchor_status["error_type"] = "insufficient_funds"
                        anchor_status["hint"] = f"{signer_kind} signer {signer_address} does not have enough ETH for gas."
                    elif "nonce" in error_str:
                        anchor_status["error_type"] = "nonce_issue"
                        anchor_status["hint"] = "Transaction nonce conflict. A previous tx may be pending."
                    elif "execution reverted" in error_str:
                        anchor_status["error_type"] = "execution_reverted"
                        anchor_status["hint"] = "Contract call reverted. Check signer authorization in your business contract."
                    else:
                        anchor_status["error_type"] = "sign_or_broadcast_failed"

            result.update(anchor_status)

        return result
    except Exception as e:
        logger.error(f"Failed to save to storage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage/{key}")
def load_from_storage(key: str):
    """
    Load key-value data from S3 storage.
    
    Returns the stored JSON value for the given key.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        # Try to load from S3
        data = odyn.s3_get(key)
        
        if data is None:
            raise HTTPException(status_code=404, detail=f"Key not found: {key}")
        
        # Parse JSON
        value = json.loads(data.decode('utf-8'))

        result: Dict[str, Any] = {
            "key": key,
            "value": value,
            "s3_encryption_mode": S3_ENCRYPTION_MODE,
        }

        # Verify user_settings key against on-chain state hash
        if key == "user_settings":
            if not CONTRACT_ADDRESS:
                result["verified"] = None
                result["verification_note"] = "App contract not configured (CONTRACT_ADDRESS is empty)"
            else:
                # Normalize value: if it's a string that looks like JSON, parse it
                verify_value = value
                if isinstance(value, str):
                    try:
                        verify_value = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        pass  # Keep as string if not valid JSON

                if not isinstance(verify_value, dict):
                    result["verified"] = None
                    result["verification_note"] = "Cannot verify: stored value is not a JSON object"
                else:
                    onchain_hash = get_onchain_state_hash(contract_address=CONTRACT_ADDRESS)
                    computed_hash = compute_state_hash(verify_value)
                    result["onchain_hash"] = onchain_hash
                    result["computed_hash"] = computed_hash
                    if not onchain_hash:
                        result["verified"] = None
                        result["verification_note"] = "On-chain state hash is empty (not yet anchored)"
                    elif computed_hash.lower() == onchain_hash.lower():
                        result["verified"] = True
                    else:
                        result["verified"] = False
                        result["error"] = "State hash mismatch; S3 data is not trusted"

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to load from storage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage")
def list_storage():
    """
    List all keys in S3 storage.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        res = odyn.s3_list()
        keys = res.get("keys", []) if isinstance(res, dict) else res
        return {
            "keys": keys,
            "count": len(keys),
            "continuation_token": res.get("continuation_token") if isinstance(res, dict) else None,
            "is_truncated": res.get("is_truncated") if isinstance(res, dict) else False,
            "s3_encryption_mode": S3_ENCRYPTION_MODE,
        }
    except Exception as e:
        logger.error(f"Failed to list storage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/storage/{key}")
def delete_from_storage(key: str):
    """
    Delete a key from S3 storage.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    try:
        success = odyn.s3_delete(key)
        
        # Also remove from in-memory state
        if app_state and key in app_state.get("data", {}):
            del app_state["data"][key]
        
        return {
            "success": success,
            "key": key,
            "message": f"Key deleted from S3 storage",
            "s3_encryption_mode": S3_ENCRYPTION_MODE,
        }
    except Exception as e:
        logger.error(f"Failed to delete from storage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Contract Interaction Demo
# =============================================================================

# Contract configuration
# This template uses static constants in config.py (per-request: no env var reads).


@router.get("/contract")
def read_contract():
    """
    Read state from the NovaAppBase contract.
    
    Returns:
        - stateHash: Current state hash stored on-chain
        - teeWallet: Registered TEE wallet address
        - lastUpdatedBlock: Block number of last update
    """
    if not CONTRACT_ADDRESS:
        return {
            "error": "Contract not configured",
            "hint": "Set CONTRACT_ADDRESS in enclave/config.py"
        }
    
    # Note: For full contract reads, you would use web3.py or similar
    # This is a demo showing the pattern
    return {
        "contract_address": CONTRACT_ADDRESS,
        "rpc_url": _chain.endpoint,
        "chain_name": BUSINESS_CHAIN_NAME,
        "chain_id": BUSINESS_CHAIN_ID,
        "tee_address": Web3.to_checksum_address(odyn.eth_address()) if odyn else None,
        "note": "Full contract read requires web3.py integration"
    }


@router.post("/contract/update-state")
def update_contract_state(req: ContractWriteRequest):
    """
    Update state hash on the NovaAppBase contract.
    
    This signs a transaction (app wallet preferred, TEE wallet fallback)
    and returns the raw tx.
    The transaction can be submitted via any RPC endpoint.
    
    Note: For full implementation, add web3.py for nonce/gas estimation.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")
    
    if not CONTRACT_ADDRESS:
        raise HTTPException(
            status_code=400, 
            detail="Contract not configured. Set CONTRACT_ADDRESS in enclave/config.py."
        )
    
    try:
        signer_kind, signer_address, sign_tx_fn = _resolve_tx_signer()
        signed = sign_update_state_hash(
            odyn=odyn,
            contract_address=CONTRACT_ADDRESS,
            chain_id=BUSINESS_CHAIN_ID,
            state_hash=req.state_hash,
            broadcast=BROADCAST_TX,
            sign_tx_fn=sign_tx_fn,
            sender_address=signer_address,
            signer_kind=signer_kind,
        )
        return {
            "success": True,
            "raw_transaction": signed["raw_transaction"],
            "transaction_hash": signed["transaction_hash"],
            "from_address": signed["address"],
            "tx_signer": signer_kind,
            "to_address": CONTRACT_ADDRESS,
            "broadcasted": signed.get("broadcasted"),
            "rpc_tx_hash": signed.get("rpc_tx_hash"),
            "note": "Submit raw_transaction to RPC endpoint to execute" if not BROADCAST_TX else "Broadcast attempted"
        }
    except Exception as e:
        logger.error(f"Failed to sign transaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Oracle Demo (Internet to Chain)
# =============================================================================




@router.post("/oracle/update-now")
def update_oracle_price_now():
    """Fetch ETH/USD and update the on-chain app contract via updateETHPrice.

    - If BROADCAST_TX is True, the enclave will attempt to send the tx via RPC.
    - Otherwise returns a raw signed tx for the caller to broadcast.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")

    if not CONTRACT_ADDRESS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "contract_not_configured",
                "message": "App contract not configured. Set CONTRACT_ADDRESS in enclave/config.py.",
            },
        )

    # Resolve tx signer (app wallet preferred, tee wallet fallback).
    try:
        signer_kind, signer_address, sign_tx_fn = _resolve_tx_signer()
        tee_address = Web3.to_checksum_address(odyn.eth_address())
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "tx_signer_unavailable",
                "message": f"Failed to resolve tx signer: {e}",
            },
        )

    # Check signer balance
    try:
        balance_hex = _rpc_call("eth_getBalance", [signer_address, "latest"])
        balance_wei = int(balance_hex, 16)
        balance_eth = balance_wei / 1e18
        if balance_wei == 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "tx_signer_no_funds",
                    "message": f"{signer_kind} signer {signer_address} has no funds. Please send ETH to cover gas.",
                    "tx_signer": signer_kind,
                    "signer_address": signer_address,
                    "tee_address": tee_address,
                    "balance_wei": balance_wei,
                },
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to check signer balance: {e}")
        balance_eth = None

    # Fetch ETH price
    try:
        res = requests.get(
            "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
            timeout=10,
        )
        res.raise_for_status()
        price_usd = int(res.json()["ethereum"]["usd"])
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "price_fetch_failed",
                "message": f"Failed to fetch ETH/USD price from CoinGecko: {e}",
            },
        )

    updated_at = int(datetime.now(timezone.utc).timestamp())

    # Sign and optionally broadcast
    try:
        signed = sign_update_ETH_price(
            odyn=odyn,
            contract_address=CONTRACT_ADDRESS,
            chain_id=BUSINESS_CHAIN_ID,
            request_id=0,
            price_usd=price_usd,
            updated_at=updated_at,
            broadcast=BROADCAST_TX,
            sign_tx_fn=sign_tx_fn,
            sender_address=signer_address,
            signer_kind=signer_kind,
        )
    except Exception as e:
        error_str = str(e).lower()
        detail: Dict[str, Any] = {
            "error": "sign_or_broadcast_failed",
            "message": str(e),
            "tx_signer": signer_kind,
            "signer_address": signer_address,
            "tee_address": tee_address,
            "contract_address": CONTRACT_ADDRESS,
        }
        # Try to detect common issues
        if "insufficient funds" in error_str or "doesn't have enough funds" in error_str:
            detail["error"] = "insufficient_funds"
            detail["hint"] = f"{signer_kind} signer {signer_address} does not have enough ETH for gas."
        elif "nonce" in error_str:
            detail["error"] = "nonce_issue"
            detail["hint"] = "Transaction nonce conflict. A previous tx may be pending."
        elif "execution reverted" in error_str:
            detail["error"] = "execution_reverted"
            detail["hint"] = "Contract call reverted. Check signer authorization in your business contract."
        raise HTTPException(status_code=500, detail=detail)

    # Check broadcast result
    if BROADCAST_TX and signed.get("broadcasted") is False:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "broadcast_failed",
                "message": signed.get("broadcast_error", "Unknown broadcast error"),
                "tx_signer": signer_kind,
                "signer_address": signer_address,
                "tee_address": tee_address,
                "contract_address": CONTRACT_ADDRESS,
                "raw_transaction": signed.get("raw_transaction"),
            },
        )

    if app_state is not None:
        oracle_state = app_state.setdefault("data", {}).setdefault("oracle", {})
        oracle_state["last_price_usd"] = price_usd
        oracle_state["last_updated_at"] = updated_at
        oracle_state["last_reason"] = "api"
        oracle_state["last_tx"] = signed
        oracle_state["last_tx_signer"] = signer_kind

    return {
        "success": True,
        "contract_address": CONTRACT_ADDRESS,
        "tx_signer": signer_kind,
        "signer_address": signer_address,
        "tee_address": tee_address,
        "signer_balance_eth": balance_eth,
        "tee_balance_eth": balance_eth if signer_kind == "tee_wallet" else None,
        "price_usd": price_usd,
        "updated_at": updated_at,
        "tx": signed,
        "broadcast": BROADCAST_TX,
    }


def _rpc_call(method: str, params: list) -> Any:
    """RPC call with automatic failover to multiple RPC URLs."""
    return rpc_call_with_failover(method, params)


@router.get("/events/oracle")
def get_oracle_events(lookback: int = 1000):
    """Return oracle-related contract events for the last N blocks."""
    if not CONTRACT_ADDRESS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "contract_not_configured",
                "message": "App contract not configured.",
                "hint": "Set CONTRACT_ADDRESS in enclave/config.py and restart the enclave.",
            },
        )

    try:
        current_block_hex = _rpc_call("eth_blockNumber", [])
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "rpc_failed",
                "message": f"Failed to get current block number: {e}",
                "hint": "Check network connectivity and Helios status.",
                "rpc_url": _chain.endpoint,
            },
        )

    current_block = int(current_block_hex, 16)
    from_block = max(current_block - max(0, int(lookback)), 0)

    # Topics
    req_topic0 = "0x" + keccak(b"ETHPriceUpdateRequested(uint256,address)").hex()
    upd_topic0 = "0x" + keccak(b"ETHPriceUpdated(uint256,uint256,uint256,uint256)").hex()

    try:
        req_logs = _rpc_call(
            "eth_getLogs",
            [{
                "fromBlock": hex(from_block),
                "toBlock": hex(current_block),
                "address": CONTRACT_ADDRESS,
                "topics": [req_topic0],
            }],
        )
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "rpc_failed",
                "message": f"Failed to fetch ETHPriceUpdateRequested logs: {e}",
                "hint": "Check if CONTRACT_ADDRESS is correct and the contract is deployed.",
                "contract_address": CONTRACT_ADDRESS,
                "from_block": from_block,
                "to_block": current_block,
            },
        )

    try:
        upd_logs = _rpc_call(
            "eth_getLogs",
            [{
                "fromBlock": hex(from_block),
                "toBlock": hex(current_block),
                "address": CONTRACT_ADDRESS,
                "topics": [upd_topic0],
            }],
        )
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "rpc_failed",
                "message": f"Failed to fetch ETHPriceUpdated logs: {e}",
                "hint": "Check if CONTRACT_ADDRESS is correct and the contract is deployed.",
                "contract_address": CONTRACT_ADDRESS,
                "from_block": from_block,
                "to_block": current_block,
            },
        )

    handled = {}
    if app_state is not None:
        handled = app_state.get("data", {}).get("oracle", {}).get("handled_requests", {}) or {}

    def _parse_uint256(hex32: str) -> int:
        return int(hex32, 16)

    requests_out = []
    for log in req_logs or []:
        topics = log.get("topics", [])
        request_id = _parse_uint256(topics[1]) if len(topics) > 1 else 0
        requester = "0x" + topics[2][-40:] if len(topics) > 2 else None
        requests_out.append({
            "type": "ETHPriceUpdateRequested",
            "request_id": request_id,
            "requester": requester,
            "block_number": int(log.get("blockNumber", "0x0"), 16),
            "tx_hash": log.get("transactionHash"),
            "log_index": int(log.get("logIndex", "0x0"), 16),
            "handled": str(request_id) in handled,
        })

    updates_out = []
    for log in upd_logs or []:
        topics = log.get("topics", [])
        request_id = _parse_uint256(topics[1]) if len(topics) > 1 else 0
        data_hex = (log.get("data") or "0x").replace("0x", "")
        # data: priceUsd, updatedAt, blockNumber
        price_usd = int(data_hex[0:64] or "0", 16) if len(data_hex) >= 64 else 0
        updated_at = int(data_hex[64:128] or "0", 16) if len(data_hex) >= 128 else 0
        block_number_emitted = int(data_hex[128:192] or "0", 16) if len(data_hex) >= 192 else 0
        updates_out.append({
            "type": "ETHPriceUpdated",
            "request_id": request_id,
            "price_usd": price_usd,
            "updated_at": updated_at,
            "block_number_emitted": block_number_emitted,
            "block_number": int(log.get("blockNumber", "0x0"), 16),
            "tx_hash": log.get("transactionHash"),
            "log_index": int(log.get("logIndex", "0x0"), 16),
        })

    events = sorted(requests_out + updates_out, key=lambda e: (e.get("block_number", 0), e.get("log_index", 0)))

    return {
        "contract_address": CONTRACT_ADDRESS,
        "from_block": from_block,
        "to_block": current_block,
        "events": events,
        "handled_requests": handled,
    }


@router.post("/events/handle-pending")
def handle_pending_requests(lookback: int = 1000):
    """
    Scan for pending ETHPriceUpdateRequested events and handle each by
    fetching ETH/USD and submitting updateETHPrice.
    """
    if not odyn:
        raise HTTPException(status_code=500, detail="Odyn not initialized")

    if not CONTRACT_ADDRESS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "contract_not_configured",
                "message": "App contract not configured. Set CONTRACT_ADDRESS in enclave/config.py.",
            },
        )

    # Get current block
    current_block_hex = _rpc_call("eth_blockNumber", [])
    current_block = int(current_block_hex, 16)
    from_block = max(current_block - max(0, int(lookback)), 0)

    # Get request events
    req_topic0 = "0x" + keccak(b"ETHPriceUpdateRequested(uint256,address)").hex()
    req_logs = _rpc_call(
        "eth_getLogs",
        [{
            "fromBlock": hex(from_block),
            "toBlock": hex(current_block),
            "address": CONTRACT_ADDRESS,
            "topics": [req_topic0],
        }],
    )

    # Get already handled requests
    if app_state is None:
        handled = {}
    else:
        oracle_state = app_state.setdefault("data", {}).setdefault("oracle", {})
        handled = oracle_state.setdefault("handled_requests", {})

    # Find pending requests
    pending = []
    for log in req_logs or []:
        topics = log.get("topics", [])
        request_id = int(topics[1], 16) if len(topics) > 1 else 0
        if str(request_id) not in handled:
            pending.append({
                "request_id": request_id,
                "block_number": int(log.get("blockNumber", "0x0"), 16),
                "tx_hash": log.get("transactionHash"),
            })

    if not pending:
        return {
            "processed_count": 0,
            "message": "No pending requests to handle",
            "results": [],
        }

    # Resolve signer once per batch (app wallet preferred, tee wallet fallback).
    try:
        signer_kind, signer_address, sign_tx_fn = _resolve_tx_signer()
        tee_address = Web3.to_checksum_address(odyn.eth_address())
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "tx_signer_unavailable",
                "message": f"Failed to resolve tx signer: {e}",
            },
        )

    try:
        balance_hex = _rpc_call("eth_getBalance", [signer_address, "latest"])
        balance_wei = int(balance_hex, 16)
        if balance_wei == 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "tx_signer_no_funds",
                    "message": f"{signer_kind} signer {signer_address} has no funds.",
                    "tx_signer": signer_kind,
                    "signer_address": signer_address,
                    "tee_address": tee_address,
                },
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to check balance: {e}")

    # Fetch ETH price once
    try:
        res = requests.get(
            "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
            timeout=10,
        )
        res.raise_for_status()
        price_usd = int(res.json()["ethereum"]["usd"])
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "price_fetch_failed",
                "message": f"Failed to fetch ETH/USD price: {e}",
            },
        )

    updated_at = int(datetime.now(timezone.utc).timestamp())

    results = []
    for req in pending:
        request_id = req["request_id"]
        try:
            signed = sign_update_ETH_price(
                odyn=odyn,
                contract_address=CONTRACT_ADDRESS,
                chain_id=BUSINESS_CHAIN_ID,
                request_id=request_id,
                price_usd=price_usd,
                updated_at=updated_at,
                broadcast=BROADCAST_TX,
                sign_tx_fn=sign_tx_fn,
                sender_address=signer_address,
                signer_kind=signer_kind,
            )

            # Mark as handled
            handled[str(request_id)] = {
                "price_usd": price_usd,
                "updated_at": updated_at,
                "tx_hash": signed.get("transaction_hash"),
            }

            results.append({
                "request_id": request_id,
                "success": True,
                "price_usd": price_usd,
                "tx_hash": signed.get("transaction_hash"),
                "broadcasted": signed.get("broadcasted"),
                "tx_signer": signer_kind,
                "signer_address": signer_address,
            })
        except Exception as e:
            results.append({
                "request_id": request_id,
                "success": False,
                "error": str(e),
            })

    return {
        "processed_count": len(pending),
        "price_usd": price_usd,
        "tx_signer": signer_kind,
        "signer_address": signer_address,
        "tee_address": tee_address,
        "results": results,
    }


@router.get("/events/monitor")
def get_event_monitor_status():
    """
    Get event monitor status and logs.

    The enclave's background task polls for on-chain events and handles them automatically.
    This endpoint returns the current status and recent logs for frontend display.
    """
    if app_state is None:
        return {
            "status": "not_initialized",
            "message": "App state not initialized",
        }

    monitor = app_state.get("data", {}).get("event_monitor", {})
    oracle = app_state.get("data", {}).get("oracle", {})

    return {
        "status": "active" if CONTRACT_ADDRESS else "not_configured",
        "contract_address": CONTRACT_ADDRESS or None,
        "current_block": monitor.get("current_block"),
        "last_processed_block": monitor.get("last_processed_block"),
        "last_poll": monitor.get("last_poll"),
        "pending_count": monitor.get("pending_count", 0),
        "recent_events": monitor.get("recent_events", []),
        "logs": monitor.get("logs", [])[-30:],  # Last 30 logs
        "handled_requests": oracle.get("handled_requests", {}),
        "last_price_usd": oracle.get("last_price_usd"),
        "last_updated_at": oracle.get("last_updated_at"),
        "last_reason": oracle.get("last_reason"),
    }


# =============================================================================
# Add Your Own Endpoints Below
# =============================================================================

# @router.post("/your-endpoint")
# def your_endpoint(req: YourRequestModel):
#     """Your custom logic here."""
#     pass
