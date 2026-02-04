"""LLM Guard Scanner Service - FastAPI HTTP endpoints"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
import logging
import sys
from datetime import datetime

# Configure logging with clear format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Track service start time for uptime reporting
SERVICE_START_TIME = None
SCAN_COUNT = {"input": 0, "output": 0}

def validate_and_create_scanners():
    """Validate configuration and create scanners with clear error messages"""
    logger.info("=" * 60)
    logger.info("LLM Guard Scanner Service Starting")
    logger.info("=" * 60)

    try:
        from config import create_input_scanners, create_output_scanners

        logger.info("Creating input scanners...")
        input_scanners = create_input_scanners()
        logger.info(f"  ✓ {len(input_scanners)} input scanners created")

        logger.info("Creating output scanners...")
        output_scanners = create_output_scanners()
        logger.info(f"  ✓ {len(output_scanners)} output scanners created")

        logger.info("=" * 60)
        logger.info("Service initialized successfully")
        logger.info("=" * 60)

        return input_scanners, output_scanners

    except Exception as e:
        logger.error("=" * 60)
        logger.error("STARTUP FAILED - Configuration Error")
        logger.error("=" * 60)
        logger.error(f"Error: {e}")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  - Check config.py for syntax errors")
        logger.error("  - Verify language names are capitalized (Python, not python)")
        logger.error("  - Ensure all imports in config.py are valid")
        logger.error("=" * 60)
        raise

# Validate config and create scanners at import time
# This ensures we fail fast with clear error messages
from llm_guard import scan_prompt, scan_output
input_scanners, output_scanners = validate_and_create_scanners()

class ScanInputRequest(BaseModel):
    content: str
    source: Optional[str] = None  # URL, file path, etc.

class ScanOutputRequest(BaseModel):
    prompt: str
    output: str

class ScanResult(BaseModel):
    sanitized_content: str
    is_valid: bool
    risk_score: float
    threats_detected: List[str]

class HealthResponse(BaseModel):
    status: str
    input_scanner_count: int
    output_scanner_count: int
    timestamp: str
    uptime_seconds: Optional[float] = None
    scans_completed: Optional[Dict[str, int]] = None

@app.on_event("startup")
async def startup_event():
    """Record service start time"""
    global SERVICE_START_TIME
    SERVICE_START_TIME = datetime.utcnow()
    logger.info(f"Service ready at http://127.0.0.1:8765")

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with uptime and scan stats"""
    uptime = None
    if SERVICE_START_TIME:
        uptime = (datetime.utcnow() - SERVICE_START_TIME).total_seconds()

    return HealthResponse(
        status="healthy",
        input_scanner_count=len(input_scanners),
        output_scanner_count=len(output_scanners),
        timestamp=datetime.utcnow().isoformat(),
        uptime_seconds=uptime,
        scans_completed=SCAN_COUNT
    )

@app.post("/scan/input", response_model=ScanResult)
async def scan_input_content(request: ScanInputRequest):
    """Scan external content for prompt injection and sensitive data"""
    try:
        SCAN_COUNT["input"] += 1
        sanitized, results_valid, results_score = scan_prompt(
            input_scanners, request.content
        )

        # Determine threats detected
        threats = [
            scanner_name for scanner_name, is_valid 
            in results_valid.items() if not is_valid
        ]

        # Calculate overall risk score (max of all scores)
        risk_score = max(results_score.values()) if results_score else 0.0

        # Log security event if threats detected
        if threats:
            logger.warning(
                f"Threats detected: {threats}, "
                f"risk_score={risk_score}, "
                f"source={request.source}"
            )

        return ScanResult(
            sanitized_content=sanitized,
            is_valid=len(threats) == 0,
            risk_score=risk_score,
            threats_detected=threats
        )

    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/output", response_model=ScanResult)
async def scan_output_content(request: ScanOutputRequest):
    """Scan AI output for sensitive data leakage"""
    try:
        SCAN_COUNT["output"] += 1
        sanitized, results_valid, results_score = scan_output(
            output_scanners, request.prompt, request.output
        )

        threats = [
            scanner_name for scanner_name, is_valid 
            in results_valid.items() if not is_valid
        ]

        risk_score = max(results_score.values()) if results_score else 0.0

        if threats:
            logger.warning(f"Output threats detected: {threats}, risk_score={risk_score}")

        return ScanResult(
            sanitized_content=sanitized,
            is_valid=len(threats) == 0,
            risk_score=risk_score,
            threats_detected=threats
        )

    except Exception as e:
        logger.error(f"Output scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
