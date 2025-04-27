import sys
import os
from pathlib import Path
import socket
from contextlib import closing
import asyncio
import logging
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Literal
from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, field_validator, Field
import uvicorn
import json
import time
from urllib.parse import urlparse
import subprocess

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from src.core.scanners import (
    XSSScanner,
    SQLInjectionScanner,
    CSRFScanner,
    SSRFScanner,
    XXEScanner,
    IDORScanner,
    BrokenAuthScanner,
    SensitiveDataScanner,
    SecurityMisconfigScanner
)
from src.core.crawler import AdvancedCrawler
from src.config import API_KEY, API_KEY_NAME
from src.core.scanner import Scanner
from src.core.reporter import Reporter

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
static_dir = os.path.abspath(os.path.join(project_root, "src", "client", "static"))
if not os.path.exists(static_dir):
    logger.error(f"Static directory not found: {static_dir}")
    raise RuntimeError(f"Static directory not found: {static_dir}")

logger.info(f"Static files served from: {static_dir}")
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
    target_url: str = Field(..., description="The target URL to scan")
    scan_type: Literal["fast", "full"] = Field(
        default="fast",
        description="Type of scan to perform: 'fast' for quick scan or 'full' for comprehensive scan"
    )
    delay: float = Field(
        default=1.0,
        ge=0.1,
        le=5.0,
        description="Delay between requests in seconds (0.1 to 5.0)"
    )
    max_pages: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of pages to crawl (1 to 100)"
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Custom User-Agent string to use for requests"
    )

    @field_validator('target_url')
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Target URL must start with http:// or https://')
        
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError('Target URL must contain a valid domain')
            if not parsed.scheme in ('http', 'https'):
                raise ValueError('Target URL must use http:// or https:// protocol')
        except Exception as e:
            raise ValueError(f'Invalid URL format: {str(e)}')
        
        return v

    @field_validator('user_agent')
    @classmethod
    def validate_user_agent(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError('User agent cannot be empty')
            if len(v) > 255:
                raise ValueError('User agent cannot exceed 255 characters')
        return v

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
    try:
        start_time = time.time()
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Validate and prepare scanner configuration
        try:
            # Create base configuration
            base_config = {
                'timeout': 30,
                'max_retries': 3,
                'delay': config.delay,
                'user_agent': config.user_agent or 'SecScan/1.0',
                'verify_ssl': True
            }
            
            # Create scanner configuration with proper structure
            scanner_config = {
                'client': base_config.copy(),
                'crawler': {
                    'max_pages': config.max_pages,
                    'delay': config.delay,
                    'client': base_config.copy()
                },
                'scan_type': config.scan_type,
                'scanners': {
                    'xss': True,
                    'sql_injection': True,
                    'csrf': True,
                    'ssrf': True,
                    'xxe': True,
                    'idor': True,
                    'broken_auth': True,
                    'sensitive_data': True,
                    'security_misconfig': True
                }
            }
            
            logger.info(f"Created scanner configuration: {json.dumps(scanner_config, indent=2)}")
            
            # Validate configuration structure
            if not isinstance(scanner_config, dict):
                raise ValueError("Configuration must be a dictionary")
                
            if 'client' not in scanner_config:
                raise ValueError("Configuration must contain 'client' section")
                
            if 'crawler' not in scanner_config:
                raise ValueError("Configuration must contain 'crawler' section")
                
            if 'scanners' not in scanner_config:
                raise ValueError("Configuration must contain 'scanners' section")
                
            # Validate crawler configuration
            crawler_config = scanner_config['crawler']
            required_crawler_fields = ['max_pages', 'delay', 'client']
            for field in required_crawler_fields:
                if field not in crawler_config:
                    raise ValueError(f"Crawler configuration missing required field: {field}")
                    
            # Validate client configuration in crawler
            crawler_client_config = crawler_config['client']
            required_client_fields = ['timeout', 'max_retries', 'delay', 'user_agent', 'verify_ssl']
            for field in required_client_fields:
                if field not in crawler_client_config:
                    raise ValueError(f"Crawler client configuration missing required field: {field}")
                    
        except ValueError as e:
            logger.error(f"Configuration validation failed: {str(e)}")
            logger.error(f"Configuration structure: {json.dumps(scanner_config, indent=2)}")
            await log_manager.broadcast(f"Configuration error: {str(e)}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid configuration: {str(e)}"
            )
            
        # Initialize scanner
        try:
            logger.info("Initializing scanner with configuration")
            scanner = Scanner(scanner_config)
            logger.info("Scanner initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {str(e)}")
            logger.error(f"Configuration used: {json.dumps(scanner_config, indent=2)}")
            await log_manager.broadcast(f"Scanner initialization failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Scanner initialization failed: {str(e)}"
            )
        
        # Start scanning
        await log_manager.broadcast(f"Starting scan of {config.target_url}")
        await log_manager.broadcast(f"Scan type: {config.scan_type}")
        await log_manager.broadcast(f"Using scanners: {', '.join([k for k, v in scanner_config['scanners'].items() if v])}")
        
        # Run the scan
        try:
            results = await scanner.scan(config.target_url)
        except Exception as e:
            logger.error(f"Scan execution failed: {str(e)}")
            await log_manager.broadcast(f"Scan execution failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Scan execution failed: {str(e)}"
            )
        
        # Store results
        scan_results[scan_id] = {
            'scan_id': scan_id,
            'status': 'completed',
            'target_url': config.target_url,
            'scan_type': config.scan_type,
            'start_time': start_time,
            'end_time': time.time(),
            'results': results
        }
        
        await log_manager.broadcast("Scan completed successfully")
        
        return scan_results[scan_id]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during scan: {str(e)}")
        await log_manager.broadcast(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )

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
        # Accept the connection first
        await websocket.accept()
        
        # Get the API key from the query parameters
        api_key = websocket.query_params.get('api_key')
        if not api_key or api_key != API_KEY:
            logger.warning("Invalid or missing API key in WebSocket connection")
            await websocket.close(code=1008, reason="Invalid API key")
            return
            
        # Get the selected protocol
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

def generate_ssl_certificates():
    """Generate self-signed SSL certificates if they don't exist."""
    key_path = Path('key.pem')
    cert_path = Path('cert.pem')
    
    if not key_path.exists() or not cert_path.exists():
        logger.info("Generating self-signed SSL certificates...")
        try:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', str(key_path), '-out', str(cert_path),
                '-days', '365', '-nodes', '-subj', '/CN=localhost'
            ], check=True)
            logger.info("SSL certificates generated successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate SSL certificates: {e}")
            raise

def start_server():
    """Start the FastAPI server with SSL configuration."""
    generate_ssl_certificates()
    
    app = FastAPI()
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Mount static files
    static_dir = Path(__file__).parent.parent / "client" / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    # Find a free port
    port = find_free_port()
    logger.info(f"Starting server on port {port}")
    
    # Start the server
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )

if __name__ == "__main__":
    start_server() 