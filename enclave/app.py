"""
=============================================================================
Nova App Template - Main Application (app.py)
=============================================================================

This is the main entry point for your Nova TEE application.

┌─────────────────────────────────────────────────────────────────────────────┐
│  DO NOT MODIFY THIS FILE                                                    │
│  Instead, add your business logic to:                                       │
│    - routes.py  → API endpoints (public + /api)                             │
│    - tasks.py   → Background jobs / cron tasks                              │
└─────────────────────────────────────────────────────────────────────────────┘

Architecture:
    ┌──────────────┐     ┌──────────────┐     ┌───────────────────────┐
    │   routes.py  │     │   tasks.py   │     │  nova_python_sdk/*    │
    │ Public + /api│     │  (User Cron) │     │ Canonical platform    │
    └──────┬───────┘     └──────┬───────┘     │ helpers               │
           │                    │             └───────────┬───────────┘
           └────────────────────┼──────────────────────────┘
                                │
                         ┌──────┴───────┐
                         │    app.py    │
                         │  (Framework) │
                         └──────────────┘

`app.py` owns the shared `Odyn()` instance from `enclave/nova_python_sdk/`
and passes it into `routes.init()` and `tasks.init()`. Keep reusable Nova /
Enclaver API wrappers in `nova_python_sdk/`, and keep app-specific route, task,
and contract logic in `routes.py`, `tasks.py`, and `chain.py`.
"""

import logging
import json
import os
from pathlib import Path
from typing import Optional
from web3 import Web3

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

# Platform & User Components
from nova_python_sdk.odyn import Odyn
import tasks
import routes
import config

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nova-app")

# =============================================================================
# FastAPI Application Instance
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Called when the application starts and stops.
    """
    # Startup
    logger.info("Starting Nova App...")
    
    # 1. Initialize user modules with shared references
    from chain import wait_for_helios
    try:
        # We try to wait for Helios. If it's not enabled in Nova UI, 
        # this will eventually timeout or fail, which is correct for 
        # an app that requires verifiable blockchain access.
        wait_for_helios(timeout=30) 
    except Exception as e:
        logger.warning(f"Helios sync wait skipped/failed: {e}")

    tasks.init(app_state, odyn)
    routes.init(app_state, odyn)
    
    # 2. Register user routes (prefix: /api) and public routes
    app.include_router(routes.public_router)
    app.include_router(routes.router)
    
    # 3. Load persisted state from S3 via Odyn.
    # In local mockup mode this can be unavailable; if so we log and continue
    # with an empty state so local development still comes up cleanly.
    try:
        data_bytes = odyn.s3_get("app_state.json")
        if data_bytes:
            app_state["data"] = json.loads(data_bytes.decode('utf-8'))
            logger.info("State loaded from S3")
        else:
            logger.info("No previous state found, starting fresh")
        app_state["initialized"] = True
    except Exception as e:
        logger.warning(f"Starting fresh (could not load state): {e}")
        app_state["initialized"] = True

    # 4. Start background scheduler
    scheduler.start()
    logger.info("Nova App started successfully")
    
    yield
    
    # Shutdown
    scheduler.shutdown()
    logger.info("Nova App shutdown complete")

app = FastAPI(
    title="Nova App",
    description="A verifiable TEE application on Nova Platform",
    version="1.0.0",
    lifespan=lifespan
)

# =============================================================================
# CORS Configuration
# =============================================================================
# Allow API access from frontends hosted on different domains.
# Configure allowed origins via CORS_ORIGINS env (comma-separated) or "*".
# If "*", any Origin is matched (via regex) so arbitrary hosts can call the API.
# Set CORS_ALLOW_CREDENTIALS to enable cookies/authorization for cross-origin requests.
# Note: current Nova deploy modal has no dedicated env-var input section.
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
cors_allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() in ("1", "true", "yes")

cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
if not cors_origins:
    cors_origins = ["*"]

allow_all_origins = "*" in cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[] if allow_all_origins else cors_origins,
    allow_origin_regex=".*" if allow_all_origins else None,
    allow_credentials=cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Frontend Static Files (optional, for bundled static UI)
# =============================================================================
FRONTEND_DIR = Path(__file__).parent / "frontend"

# Mount frontend static files if the directory exists
if FRONTEND_DIR.exists():
    app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
    logger.info(f"Frontend mounted at /frontend from {FRONTEND_DIR}")
else:
    logger.warning(f"Frontend directory not found: {FRONTEND_DIR}")


# =============================================================================
# Shared State & Platform SDK
# =============================================================================
# Odyn: interface to enclave runtime services.
# Endpoint resolution order:
#   1. explicit constructor argument
#   2. ODYN_API_BASE_URL / ODYN_ENDPOINT
#   3. 127.0.0.1:18000 when IN_ENCLAVE=true
#   4. odyn.sparsity.cloud:18000 in local development
odyn = Odyn()

# Application state: Shared across routes.py and tasks.py
# - "data": Your application's persistent data (saved to S3)
# - "initialized": True after startup completes
app_state = {
    "initialized": False, 
    "data": {},           # Your app data goes here
    "last_cron_run": None,
    "cron_counter": 0
}

# =============================================================================
# Platform Endpoints (do not modify)
# =============================================================================
class AppStatus(BaseModel):
    """Response model for /status endpoint."""
    status: str
    ETH_address: Optional[str] = None
    contract_address: Optional[str] = None
    cron_info: Optional[dict] = None
    last_state_hash: Optional[str] = None

@app.get("/health")
def health_check():
    """Health check endpoint for load balancers."""
    return {"status": "healthy"}


@app.get("/")
def root_overview(request: Request):
    """Simple app landing payload with frontend URL and API overview."""
    base_url = str(request.base_url).rstrip("/")
    return {
        "app": "Nova App Template",
        "message": "Frontend UI and API are ready.",
        "frontend": {
            "primary_url": f"{base_url}/frontend",
            "note": "If Next.js frontend is hosted separately, use that deployed frontend URL instead.",
        },
        "api_overview": [
            {"endpoint": "GET /health", "description": "Health check"},
            {"endpoint": "GET /status", "description": "TEE/app runtime status"},
            {"endpoint": "POST /.well-known/attestation", "description": "Public Nitro attestation document"},
            {"endpoint": "GET /api/encryption/public_key", "description": "TEE encryption public key"},
            {"endpoint": "POST /api/echo", "description": "Secure echo demo"},
            {"endpoint": "GET /api/random", "description": "Nitro hardware entropy demo"},
            {"endpoint": "POST /api/storage", "description": "Store value to S3"},
            {"endpoint": "GET /api/storage/{key}", "description": "Read value from S3"},
            {"endpoint": "GET /api/storage/config", "description": "S3 encryption mode diagnostics"},
            {"endpoint": "GET /api/filesystem/config", "description": "File proxy mount diagnostics"},
            {"endpoint": "POST /api/filesystem/write", "description": "Write a file into the mounted filesystem"},
            {"endpoint": "GET /api/filesystem/read?path=...", "description": "Read a file from the mounted filesystem"},
            {"endpoint": "GET /api/filesystem/list", "description": "List files in the mounted filesystem"},
            {"endpoint": "GET /api/app-wallet/address", "description": "Get app wallet address"},
            {"endpoint": "POST /api/app-wallet/sign", "description": "Sign message with app wallet"},
            {"endpoint": "GET /api/enclaver/features", "description": "Enclaver capability snapshot"},
        ],
    }

@app.get("/status", response_model=AppStatus)
def get_status():
    """Get TEE identity and cron status."""
    try:
        address = Web3.to_checksum_address(odyn.eth_address())
        return AppStatus(
            status="running",
            ETH_address=address,
            contract_address=config.CONTRACT_ADDRESS or None,
            cron_info={
                "counter": app_state["cron_counter"],
                "last_run": app_state["last_cron_run"]
            },
            last_state_hash=app_state["data"].get("last_state_hash")
        )
    except Exception as e:
        return AppStatus(status=f"degraded: {e}")

# =============================================================================
# Background Scheduler (Cron)
# =============================================================================
# Runs tasks.background_task() every 5 minutes
# Modify the interval in scheduler.add_job() if needed
scheduler = BackgroundScheduler()
scheduler.add_job(tasks.background_task, 'interval', minutes=5)

# Poll on-chain events more frequently for near-real-time reactions
scheduler.add_job(tasks.poll_contract_events, 'interval', seconds=30)

# Periodic oracle price update (default every 15 minutes)
scheduler.add_job(tasks.oracle_periodic_update, 'interval', minutes=tasks.ORACLE_PRICE_UPDATE_MINUTES)

# =============================================================================
# Application Lifecycle
# =============================================================================


# =============================================================================
# Development Entry Point
# =============================================================================
if __name__ == "__main__":
    # This port must match the "App Listening Port" value entered when 
    # creating the app on the Nova platform.
    # The portal can parse ingress.listen_port from repo enclaver.yaml when creating an app.
    uvicorn.run(app, host="0.0.0.0", port=8000)
