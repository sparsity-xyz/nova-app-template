.PHONY: dev-backend dev-frontend build-frontend build-enclave build-docker

dev-backend:
	cd enclave && IN_ENCLAVE=false python3 app.py

dev-frontend:
	cd frontend && npm run dev

build-frontend:
	cd frontend && npm install && npm run build
	rm -rf enclave/frontend
	mkdir -p enclave/frontend
	# Next.js export goes to 'out'
	cp -r frontend/out/* enclave/frontend/

build-docker:
	docker build -t nova-app-template:latest .

build-enclave:
	enclaver build
