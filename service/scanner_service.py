"""LLM Guard Scanner Service - FastAPI HTTP endpoints"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
import logging
from datetime import datetime

from llm_guard import scan_prompt, scan_output
from config import create_input_scanners, create_output_scanners

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LLM Guard Scanner Service", version="1.0.0")

# Initialize scanners at startup
input_scanners = create_input_scanners()
output_scanners = create_output_scanners()

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

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        input_scanner_count=len(input_scanners),
        output_scanner_count=len(output_scanners),
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/scan/input", response_model=ScanResult)
async def scan_input_content(request: ScanInputRequest):
    """Scan external content for prompt injection and sensitive data"""
    try:
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
