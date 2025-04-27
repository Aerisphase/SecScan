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
from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uvicorn
import json
import time

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from src.core.scanners.xss import XSSScanner
from src.core.scanners.sqli import SQLiScanner
from src.core.crawler import AdvancedCrawler
from src.config import API_KEY, API_KEY_NAME
from src.core.scanner import Scanner
from src.core.reporter import Reporter
from src.server.recommendations import RecommendationResponse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
    expose_headers=["*"]
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
    recommendations: List[RecommendationResponse] = []
    timestamp: datetime

# In-memory storage for scan results (replace with database in production)
scan_results = {}

# WebSocket manager for log streaming
class LogManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger('WebSocket')
        self.connection_lock = asyncio.Lock()
        self.broadcast_lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        try:
            async with self.connection_lock:
                self.active_connections.append(websocket)
                self.logger.info(f"New WebSocket connection established. Total connections: {len(self.active_connections)}")
        except Exception as e:
            self.logger.error(f"Failed to establish WebSocket connection: {str(e)}")
            raise

    async def disconnect(self, websocket: WebSocket):
        async with self.connection_lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
                self.logger.info(f"WebSocket connection closed. Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        async with self.broadcast_lock:
            if not self.active_connections:
                self.logger.warning("No active WebSocket connections to broadcast to")
                return
                
            disconnected = []
            async with self.connection_lock:
                for connection in self.active_connections:
                    try:
                        # Format message as JSON
                        message_json = json.dumps({"message": message})
                        await connection.send_text(message_json)
                        self.logger.debug(f"Broadcasted message: {message}")
                    except Exception as e:
                        self.logger.error(f"Error broadcasting message: {str(e)}")
                        disconnected.append(connection)
            
            # Remove disconnected connections
            for connection in disconnected:
                await self.disconnect(connection)

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
    return {"message": "SecScan API is running"}

@app.post("/scan")
async def start_scan(config: ScanRequest, api_key: str = Depends(get_api_key)):
    """Start a new scan"""
    try:
        scan_id = secrets.token_urlsafe(16)
        scanner = Scanner(
            target_url=config.target_url,
            scan_type=config.scan_type,
            delay=config.delay,
            max_pages=config.max_pages,
            user_agent=config.user_agent
        )
        
        # Start scan in background
        asyncio.create_task(run_scan(scanner, scan_id))
        
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_scan(scanner: Scanner, scan_id: str):
    """Run the scan and store results"""
    try:
        results = await scanner.scan()
        
        # Get recommendations for each vulnerability
        recommendations = []
        for vuln in results['vulnerabilities']:
            vuln_recommendations = recommender.get_recommendations({
                'type': vuln['type'],
                'description': vuln['description']
            })
            recommendations.extend(vuln_recommendations)
        
        # Store results with recommendations
        scan_results[scan_id] = {
            'scan_id': scan_id,
            'status': 'completed',
            'stats': results['stats'],
            'vulnerabilities': results['vulnerabilities'],
            'recommendations': recommendations,
            'timestamp': datetime.now()
        }
    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {e}")
        scan_results[scan_id] = {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
            'timestamp': datetime.now()
        }

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
        # Accept connection with protocol validation
        await websocket.accept(subprotocol='v1.secscan')
        
        # Get the selected protocol from the client
        selected_protocol = websocket.headers.get('sec-websocket-protocol')
        if selected_protocol != 'v1.secscan':
            logger.warning(f"Invalid protocol: {selected_protocol}")
            await websocket.close(code=1002, reason="Invalid protocol")
            return
            
        await log_manager.connect(websocket)
        logger.info("WebSocket connection established successfully")
        
        try:
            while True:
                try:
                    # Wait for message or timeout
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                    
                    # Handle ping messages
                    try:
                        message = json.loads(data)
                        if message.get('type') == 'ping':
                            await websocket.send_text(json.dumps({'type': 'pong'}))
                            continue
                        elif message.get('type') == 'pong':
                            continue
                        else:
                            await log_manager.broadcast(json.dumps(message))
                    except json.JSONDecodeError:
                        logger.warning(f"Received invalid JSON message: {data}")
                        
                except asyncio.TimeoutError:
                    # Send ping to keep connection alive
                    await websocket.send_text(json.dumps({'type': 'ping'}))
                    continue
                    
        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {str(e)}")
            await websocket.close(code=1011, reason="Internal server error")
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except:
            pass
    finally:
        try:
            await log_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"Error during WebSocket cleanup: {str(e)}")

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