#!/bin/sh
set -e

# Data directory for persistent storage (mapped to Unraid /mnt/user/appdata/netpulse)
DATA_DIR="${NETPULSE_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# Seed default database if it doesn't exist yet in persistent storage
if [ ! -f "$DATA_DIR/netpulse.db" ] && [ -f "/app/netpulse.db" ]; then
    echo "Seeding initial NetPulse database to $DATA_DIR/netpulse.db..."
    cp "/app/netpulse.db" "$DATA_DIR/netpulse.db"
fi

export NETPULSE_DATA_DIR="$DATA_DIR"
export NETPULSE_DB_PATH="$DATA_DIR/netpulse.db"

exec "$@"
