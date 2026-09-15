#!/bin/bash
# NetPulse - Launcher Script

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "============================================================"
echo "  ⚡ NetPulse - Network Analyzer & Sentinel Dashboard"
echo "============================================================"
echo "  Iniciando motor de rede e servidor local..."
echo "  Abrindo navegador em: http://localhost:8888"
echo "============================================================"

# Open default browser after 1.5 seconds in background
(sleep 1.5 && open "http://localhost:8888") &

# Start python server
python3 server.py
