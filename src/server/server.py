import sys
import os
from pathlib import Path
import socket
from contextlib import closing
import asyncio
import logging
import secrets
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uvicorn

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from src.core.scanners.xss import XSSScanner
from src.core.scanners.sqli import SQLiScanner
from src.core.crawler import AdvancedCrawler
from src.config import API_KEY, API_KEY_NAME

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detailed logs
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

# WebSocket manager for log streaming
class LogManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger('WebSocket')

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"New WebSocket connection established. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        self.logger.info(f"WebSocket connection closed. Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        if not self.active_connections:
            self.logger.warning("No active WebSocket connections to broadcast to")
            return
            
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
                self.logger.debug(f"Broadcasted message: {message}")
            except Exception as e:
                self.logger.error(f"Error broadcasting message: {str(e)}")
                self.disconnect(connection)

log_manager = LogManager()

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
        
        await log_manager.broadcast(f"Starting scan {scan_id} for {request.target_url}")
        
        crawler = AdvancedCrawler(request.target_url, config)
        crawl_data = crawler.crawl()
        
        if not crawl_data:
            await log_manager.broadcast(f"Scan {scan_id} failed: Failed to crawl target")
            raise HTTPException(status_code=400, detail="Failed to crawl target")
        
        await log_manager.broadcast(f"Scan {scan_id}: Crawled {crawl_data.get('pages_crawled', 0)} pages")
        
        # Run scanners
        scanners = {
            'xss': XSSScanner(crawler.client),
            'sqli': SQLiScanner(crawler.client)
        }
        
        vulnerabilities = []
        for scanner_name, scanner in scanners.items():
            try:
                await log_manager.broadcast(f"Scan {scan_id}: Running {scanner_name.upper()} scanner...")
                vulns = scanner.scan(request.target_url, crawl_data.get('forms', []))
                if vulns:
                    vulnerabilities.extend(vulns)
                    await log_manager.broadcast(f"Scan {scan_id}: Found {len(vulns)} {scanner_name.upper()} vulnerabilities")
            except Exception as e:
                error_msg = f"{scanner_name} scanner failed: {str(e)}"
                await log_manager.broadcast(f"Scan {scan_id}: {error_msg}")
                logger.error(error_msg)
        
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
        await log_manager.broadcast(f"Scan {scan_id} completed successfully")
        return result
        
    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        await log_manager.broadcast(error_msg)
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str, api_key: str = Depends(get_api_key)):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

# Add WebSocket endpoint
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    logger.info("New WebSocket connection attempt")
    try:
        await log_manager.connect(websocket)
        while True:
            try:
                data = await websocket.receive_text()
                logger.debug(f"Received message: {data}")
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                logger.info("WebSocket client disconnected")
                break
            except Exception as e:
                logger.error(f"WebSocket error: {str(e)}")
                break
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
    finally:
        log_manager.disconnect(websocket)

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
        
        # Configure uvicorn with proper shutdown handling
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=port,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
            log_level="info",
            loop="asyncio",
            timeout_keep_alive=30
        )
        server = uvicorn.Server(config)
        server.run()
        
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        sys.exit(1) 