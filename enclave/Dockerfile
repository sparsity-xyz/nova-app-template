FROM python:3.11-slim

WORKDIR /app

# Default to mock mode outside enclave;
ENV IN_ENCLAVE=false

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py odyn.py routes.py tasks.py ./
COPY frontend-dist/ ./frontend-dist/ 2>/dev/null || true

# Expose the "App Listening Port" (must match enclaver.yaml ingress)
EXPOSE 8000

# Run the application
CMD ["python", "app.py"]
