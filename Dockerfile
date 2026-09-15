FROM python:3.12-slim

WORKDIR /app

# Install essential network tools for ARP discovery, ICMP ping, and routing
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    net-tools \
    iputils-ping \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
