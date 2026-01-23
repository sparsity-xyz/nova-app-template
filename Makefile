# =============================================================================
# Nova App Template - Makefile
# =============================================================================
# 
# Build and development commands for the Nova App Template.
#
# Usage:
#   make build-frontend    Build and copy frontend to enclave
#   make dev-frontend      Start frontend dev server
#   make dev-enclave       Start enclave dev server
#   make clean             Clean build artifacts
#   make help              Show this help
# =============================================================================

.PHONY: all build-frontend dev-frontend dev-enclave clean help

# Directories
FRONTEND_DIR := frontend
ENCLAVE_DIR := enclave
FRONTEND_DIST := $(ENCLAVE_DIR)/frontend-dist

# Default target
all: build-frontend

# =============================================================================
# Frontend Commands
# =============================================================================

## Install frontend dependencies
install-frontend:
	cd $(FRONTEND_DIR) && npm install

## Build frontend and copy to enclave/frontend-dist
build-frontend: install-frontend
	@echo "Building frontend..."
	cd $(FRONTEND_DIR) && npm run build
	@echo "Copying frontend build to enclave..."
	rm -rf $(FRONTEND_DIST)
	cp -r $(FRONTEND_DIR)/out $(FRONTEND_DIST)
	@echo "Frontend build complete: $(FRONTEND_DIST)"

## Start frontend development server
dev-frontend:
	cd $(FRONTEND_DIR) && npm run dev

# =============================================================================
# Enclave Commands
# =============================================================================

## Install enclave dependencies
install-enclave:
	cd $(ENCLAVE_DIR) && pip install -r requirements.txt

## Start enclave development server
dev-enclave: install-enclave
	cd $(ENCLAVE_DIR) && python app.py

# =============================================================================
# Docker Commands
# =============================================================================

## Build Docker image
docker-build: build-frontend
	cd $(ENCLAVE_DIR) && docker build -t nova-app:latest .

## Run Docker container locally
docker-run:
	docker run -p 8000:8000 nova-app:latest

# =============================================================================
# Cleanup
# =============================================================================

## Clean build artifacts
clean:
	rm -rf $(FRONTEND_DIR)/out
	rm -rf $(FRONTEND_DIR)/.next
	rm -rf $(FRONTEND_DIR)/node_modules
	rm -rf $(FRONTEND_DIST)
	find $(ENCLAVE_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find $(ENCLAVE_DIR) -type d -name ".venv" -exec rm -rf {} + 2>/dev/null || true

# =============================================================================
# Help
# =============================================================================

help:
	@echo "Nova App Template - Available Commands"
	@echo ""
	@echo "Frontend:"
	@echo "  make install-frontend  Install frontend npm dependencies"
	@echo "  make build-frontend    Build frontend and copy to enclave/frontend-dist"
	@echo "  make dev-frontend      Start frontend dev server (port 3000)"
	@echo ""
	@echo "Enclave:"
	@echo "  make install-enclave   Install enclave Python dependencies"
	@echo "  make dev-enclave       Start enclave dev server (port 8000)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build      Build Docker image (includes frontend)"
	@echo "  make docker-run        Run Docker container locally"
	@echo ""
	@echo "Other:"
	@echo "  make clean             Clean all build artifacts"
	@echo "  make help              Show this help"
