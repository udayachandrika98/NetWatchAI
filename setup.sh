#!/bin/bash
# NetWatchAI - One-Command Setup
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/NetWatchAI/main/setup.sh | bash

set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   NetWatchAI - AI Intrusion Detection    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        echo "Docker installed! You may need to log out and back in, then re-run this script."
        exit 0
    else
        echo "Please install Docker Desktop from: https://docs.docker.com/desktop/"
        exit 1
    fi
fi

# Check if Docker is running
if ! docker info &> /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi

echo "[1/2] Starting NetWatchAI..."
docker run -d \
    --name netwatchai \
    -p 8501:8501 \
    --restart unless-stopped \
    udayak/netwatchai:latest 2>/dev/null || {
        # Container name already exists — restart it
        docker start netwatchai 2>/dev/null
    }

echo "[2/2] Waiting for dashboard..."
for i in {1..30}; do
    if curl -sf http://localhost:8501/_stcore/health > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo ""
echo "  ✅ NetWatchAI is running!"
echo "  🌐 Open: http://localhost:8501"
echo ""
echo "  Commands:"
echo "    Stop:    docker stop netwatchai"
echo "    Start:   docker start netwatchai"
echo "    Remove:  docker rm -f netwatchai"
echo "    Logs:    docker logs -f netwatchai"
echo ""

# Open browser automatically
if command -v open &> /dev/null; then
    open http://localhost:8501
elif command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8501
fi
