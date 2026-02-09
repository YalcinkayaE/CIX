# Stage 1: Builder
FROM python:3.12-slim as builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /root/.local /root/.local

# Ensure scripts in .local are usable:
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY src/ ./src/
COPY main.py .
COPY *.json .

# Create data directory for volume mapping
RUN mkdir data

# Default entrypoint: API service
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8009"]
