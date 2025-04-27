from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
from ai.vulnerability_analyzer import VulnerabilityAnalyzer
from ai.recommender import VulnerabilityRecommender

# Load environment variables
load_dotenv()

app = FastAPI(title="SecScan API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize vulnerability analyzer and recommender
analyzer = VulnerabilityAnalyzer()
recommender = VulnerabilityRecommender()

class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "fast"
    max_pages: Optional[int] = 20
    delay: Optional[float] = 0.1
    user_agent: Optional[str] = None

class Vulnerability(BaseModel):
    type: str
    url: str
    payload: str
    evidence: str
    severity: str
    param: Optional[str] = None
    method: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    scan_type: str
    timestamp: str
    elapsed_time: float
    stats: Dict
    vulnerabilities: List[Vulnerability]
    security_recommendations: List[str]

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    try:
        # Validate API key
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != os.getenv("SECSCAN_API_KEY"):
            raise HTTPException(status_code=403, detail="Invalid API key")

        # Start scan (simplified for example)
        scan_result = {
            "scan_id": "test_scan_123",
            "target_url": request.target_url,
            "scan_type": request.scan_type,
            "timestamp": "2023-01-01T00:00:00Z",
            "elapsed_time": 2.5,
            "stats": {
                "pages_crawled": 5,
                "total_vulnerabilities": 3,
                "severity_counts": {
                    "critical": 1,
                    "high": 2,
                    "medium": 0,
                    "low": 0
                }
            },
            "vulnerabilities": [
                {
                    "type": "SQL Injection",
                    "url": f"{request.target_url}/login",
                    "payload": "' OR '1'='1",
                    "evidence": "SQL error detected",
                    "severity": "critical",
                    "param": "username",
                    "method": "POST"
                },
                {
                    "type": "XSS",
                    "url": f"{request.target_url}/search",
                    "payload": "<script>alert('XSS')</script>",
                    "evidence": "XSS payload found in response",
                    "severity": "high",
                    "param": "q",
                    "method": "GET"
                }
            ],
            "security_recommendations": []
        }

        # Get AI-based recommendations for each vulnerability
        for vuln in scan_result["vulnerabilities"]:
            recommendations, confidence = recommender.get_recommendations(
                vuln["type"],
                f"URL: {vuln['url']}, Method: {vuln['method']}, Param: {vuln['param']}"
            )
            vuln["recommendations"] = recommendations
            vuln["confidence"] = confidence

        # Get preventive measures
        preventive_measures = recommender.get_preventive_measures(
            f"Scanning {request.target_url} with {request.scan_type} scan"
        )
        scan_result["security_recommendations"] = preventive_measures

        return scan_result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, ssl_keyfile="key.pem", ssl_certfile="cert.pem") 