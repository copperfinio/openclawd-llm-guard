#!/bin/bash
# LLM Guard Service Startup Script

cd "$(dirname "$0")/service"

# Activate virtual environment
source venv/bin/activate

# Export PYTHONPATH to find config module
export PYTHONPATH="$(pwd):$PYTHONPATH"

echo "Starting LLM Guard Scanner Service on port 8765..."
python scanner_service.py
