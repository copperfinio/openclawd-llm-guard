#!/usr/bin/env python3
"""Health check utility for LLM Guard service"""
import sys
import requests
from datetime import datetime

SERVICE_URL = "http://127.0.0.1:8765"

def check_health():
    """Check if the LLM Guard service is healthy"""
    try:
        response = requests.get(f"{SERVICE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data['status']}")
            print(f"Input scanners: {data['input_scanner_count']}")
            print(f"Output scanners: {data['output_scanner_count']}")
            print(f"Timestamp: {data['timestamp']}")
            return True
        else:
            print(f"Service returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("Service not running (connection refused)")
        return False
    except requests.exceptions.Timeout:
        print("Service timeout")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    healthy = check_health()
    sys.exit(0 if healthy else 1)
