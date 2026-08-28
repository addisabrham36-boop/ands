# ==============================================================================
# ANDS SENTINEL v2.0 - Docker Container
# Live SOC Analyst & Anomaly-Based Network Detection System
# ==============================================================================

FROM python:3.11-slim

# Prevent interactive prompts & Python buffering
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install required system dependencies (libpcap, net-tools, iptables for active response)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iptables \
    iproute2 \
    net-tools \
    gcc \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for caching layers
COPY requirements.txt pyproject.toml /app/

# Install python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy complete ANDS codebase
COPY . /app/

# Install ANDS in editable/develop mode
RUN pip install --no-cache-dir -e .

# Create directories for persistent volume storage
RUN mkdir -p /app/reports /app/data /app/logs

# Expose default SOC Dashboard port (avoiding 5000, 8000, 8080)
EXPOSE 8899

# Default healthcheck for web server
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8899/api/stats || exit 1

# Default command launches the unified Web SOC Dashboard
ENTRYPOINT ["python", "ands.py"]
CMD ["dashboard", "8899"]
