#!/bin/bash
# LLM Guard Service Installation Script

set -e
cd "$(dirname "$0")"

echo "=== LLM Guard Service Installation ==="

# Check Python version
python3 --version
if [ $? -ne 0 ]; then
    echo "ERROR: Python 3 not found"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "service/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv service/venv
fi

# Activate and install dependencies
echo "Installing dependencies..."
source service/venv/bin/activate
pip install --upgrade pip

# Install LLM Guard and FastAPI
pip install "llm-guard>=0.3.15" fastapi uvicorn requests "transformers>=4.40,<5.0"

echo ""
echo "=== Installation Complete ==="
echo "Run ./start.sh to start the service"
