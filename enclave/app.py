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
    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │   routes.py  │     │   tasks.py   │     │   odyn.py    │
    │ Public + /api│     │  (User Cron) │     │ (Platform)   │
    └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                    │
                ┌──────┴───────┐
                │    app.py    │
                │  (Framework) │
                └──────────────┘
"""

import logging
import json
import os
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

# Platform & User Components
from odyn import Odyn
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
app = FastAPI(
    title="Nova App",
    description="A verifiable TEE application on Nova Platform",
    version="1.0.0"
)

# =============================================================================
# CORS Configuration
# =============================================================================
# Allow API access from frontends hosted on different domains.
# Configure allowed origins via CORS_ORIGINS env (comma-separated) or "*".
# If "*", any Origin is matched (via regex) so arbitrary hosts can call the API.
# Set CORS_ALLOW_CREDENTIALS to enable cookies/authorization for cross-origin requests.
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
FRONTEND_DIR = Path(__file__).parent / "frontend-dist"

# Mount frontend static files if the directory exists
if FRONTEND_DIR.exists():
    app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
    logger.info(f"Frontend mounted at /frontend from {FRONTEND_DIR}")
else:
    logger.warning(f"Frontend directory not found: {FRONTEND_DIR}")


# =============================================================================
# Shared State & Platform SDK
# =============================================================================
# Odyn: Interface to TEE services (identity, attestation, encryption, state)
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
    eth_address: Optional[str] = None
    contract_address: Optional[str] = None
    cron_info: Optional[dict] = None
    last_state_hash: Optional[str] = None

@app.get("/health")
def health_check():
    """Health check endpoint for load balancers."""
    return {"status": "healthy"}

@app.get("/status", response_model=AppStatus)
def get_status():
    """Get TEE identity and cron status."""
    try:
        address = odyn.eth_address()
        return AppStatus(
            status="running",
            eth_address=address,
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
@app.on_event("startup")
def startup_event():
    """
    Called when the application starts.
    1. Initializes user modules with shared state
    2. Registers user-defined routes
    3. Loads encrypted state from S3
    4. Starts the background scheduler
    """
    # 1. Initialize user modules with shared references
    tasks.init(app_state, odyn)
    routes.init(app_state, odyn)
    
    # 2. Register user routes (prefix: /api) and public routes
    app.include_router(routes.public_router)
    app.include_router(routes.router)
    
    # 3. Load persisted state from S3
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

@app.on_event("shutdown")
def shutdown_event():
    """Called when the application shuts down."""
    scheduler.shutdown()
    logger.info("Nova App shutdown complete")

# =============================================================================
# Development Entry Point
# =============================================================================
if __name__ == "__main__":
    # This port must match the "App Listening Port" value entered when 
    # creating the app on the Nova platform。
    # If you specify ingress.listen_port in enclaver.yaml, it can be detected by nova platform automatically.
    uvicorn.run(app, host="0.0.0.0", port=8000)

