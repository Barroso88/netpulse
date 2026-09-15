FROM python:3.12-slim

WORKDIR /app

# Install essential network tools for ARP discovery, ICMP ping, and routing
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    net-tools \
    iputils-ping \
    iputils-arping \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for PostgreSQL support
RUN pip install --no-cache-dir psycopg2-binary

# Copy project files
COPY . /app/

# Create volume for persistent SQLite storage
VOLUME ["/data"]

# Expose port
EXPOSE 8888

# Setup entrypoint
RUN chmod +x /app/docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Start server
CMD ["python3", "server.py"]
