# Stage 1: Build the frontend
# Next.js 16 and @noble/hashes require Node >= 20.19.0.
FROM node:22-slim AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
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
COPY --from=frontend-build /frontend/out ./frontend

# Expose port 8000
EXPOSE 8000

# Run the application
CMD ["python", "app.py"]
