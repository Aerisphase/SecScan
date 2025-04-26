import sys
import os
from pathlib import Path
import socket
from contextlib import closing

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict
import uvicorn
import logging
from datetime import datetime
import secrets
import os
from src.core.scanners import SQLiScanner, XSSScanner
from src.core.crawler import AdvancedCrawler
from src.config import API_KEY, API_KEY_NAME

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Server')

def find_free_port(start_port: int = 8000, max_attempts: int = 10) -> int:
    """Find a free port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.bind(('0.0.0.0', port))
                return port
            except socket.error:
                continue
    raise RuntimeError(f"Could not find a free port after {max_attempts} attempts")

# API Key setup
api_key_header = APIKeyHeader(name=API_KEY_NAME)

app = FastAPI(title="SecScan Server", description="Secure Web Vulnerability Scanner API")

# Mount static files with absolute path
static_dir = os.path.join(project_root, "src", "client", "static")
if not os.path.exists(static_dir):
    logger.error(f"Static directory not found: {static_dir}")
    raise RuntimeError(f"Static directory not found: {static_dir}")

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "fast"
    delay: float = 1.0
    max_pages: int = 20
    user_agent: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    status: str
    stats: Dict
    vulnerabilities: List[Dict]
    timestamp: datetime

# In-memory storage for scan results (replace with database in production)
scan_results = {}

def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=403,
        detail="Invalid API Key"
    )

@app.get("/")
async def read_root():
    return {"message": "Welcome to SecScan API"}

@app.post("/scan", response_model=ScanResult)
async def start_scan(request: ScanRequest, api_key: str = Depends(get_api_key)):
    try:
        scan_id = secrets.token_urlsafe(16)
        
        # Initialize crawler and scanners
        config = {
            'max_pages': request.max_pages,
            'delay': request.delay,
            'user_agent': request.user_agent,
            'scan_type': request.scan_type
        }
        
        crawler = AdvancedCrawler(request.target_url, config)
        crawl_data = crawler.crawl()
        
        if not crawl_data:
            raise HTTPException(status_code=400, detail="Failed to crawl target")
        
        # Run scanners
        scanners = {
            'xss': XSSScanner(crawler.session),
            'sqli': SQLiScanner(crawler.session)
        }
        
        vulnerabilities = []
        for scanner_name, scanner in scanners.items():
            try:
                vulns = scanner.scan(request.target_url, crawl_data.get('forms', []))
                if vulns:
                    vulnerabilities.extend(vulns)
            except Exception as e:
                logger.error(f"{scanner_name} scanner failed: {str(e)}")
        
        # Store results
        result = ScanResult(
            scan_id=scan_id,
            status="completed",
            stats={
                'pages_crawled': crawl_data.get('pages_crawled', 0),
                'links_found': crawl_data.get('links_found', 0),
                'forms_found': crawl_data.get('forms_found', 0)
            },
            vulnerabilities=vulnerabilities,
            timestamp=datetime.now()
        )
        
        scan_results[scan_id] = result
        return result
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str, api_key: str = Depends(get_api_key)):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

if __name__ == "__main__":
    try:
        # Find a free port
        port = find_free_port(8001)  # Start from 8001
        logger.info(f"Starting server on port {port}")
        
        # Check if SSL certificates exist
        ssl_keyfile = os.path.join(project_root, "key.pem")
        ssl_certfile = os.path.join(project_root, "cert.pem")
        
        if not (os.path.exists(ssl_keyfile) and os.path.exists(ssl_certfile)):
            logger.warning("SSL certificates not found. Generating self-signed certificates...")
            os.system(f'openssl req -x509 -newkey rsa:4096 -nodes -out "{ssl_certfile}" -keyout "{ssl_keyfile}" -days 365 -subj "/CN=localhost"')
        
        logger.info(f"Server starting on https://localhost:{port}")
        logger.info(f"Static files served from: {static_dir}")
        
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=port,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile
        )
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        sys.exit(1) 