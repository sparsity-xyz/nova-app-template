# Stage 1: Build the frontend
FROM node:18-slim AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Build the enclave backend
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
ENV IN_ENCLAVE=true
COPY enclave/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code from enclave directory
COPY enclave/ .

# Copy built frontend from Stage 1 to frontend folder in /app/
# Note: echo-vault uses 'dist', but nova-app-template frontend (Next.js) uses 'out' or 'build'
# I'll check the frontend structure to be sure, but usually 'out' for static exports.
COPY --from=frontend-build /frontend/out ./frontend

# Expose port 8000
EXPOSE 8000

# Run the application
CMD ["python", "app.py"]
