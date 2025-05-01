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
from src.core.scanner_base import ScannerRegistry
from src.core.scanner import Scanner
from src.core.reporter import Reporter
# Optional AI components
try:
    from src.ai.recommender import VulnerabilityRecommender
    from src.ai.vulnerability_analyzer import VulnerabilityAnalyzer
    AI_COMPONENTS_AVAILABLE = True
except ImportError:
    VulnerabilityRecommender = None
    VulnerabilityAnalyzer = None
    AI_COMPONENTS_AVAILABLE = False
    logger.warning("AI components not available. Some features will be disabled.")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Server')

def find_free_port(start_port: int = 8000, max_attempts: int = 100) -> int:
    """Find a free port starting from start_port"""
    logger.info(f"Attempting to find a free port starting from {start_port}")
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

# Initialize the recommender
if AI_COMPONENTS_AVAILABLE:
    recommender = VulnerabilityRecommender()
    analyzer = VulnerabilityAnalyzer()
else:
    recommender = None
    analyzer = None

# Add new models
class RecommendationRequest(BaseModel):
    vulnerability: Dict
    code_context: Optional[str] = None

class RecommendationResponse(BaseModel):
    recommendations: List[str]
    severity: str
    prevention_score: float
    confidence: float

# Add new endpoints
@app.post("/recommendations", response_model=RecommendationResponse)
async def get_recommendations(request: RecommendationRequest, api_key: str = Depends(get_api_key)):
    """Get recommendations for a vulnerability"""
    if not AI_COMPONENTS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="AI-powered recommendations are not available"
        )
    
    try:
        # Get available scanner types from registry
        scanner_registry = ScannerRegistry()
        available_scanners = [scanner.name for scanner in scanner_registry.get_all_scanners()]
        
        # Enhance recommendations with scanner context
        recommendations = recommender.get_recommendations({
            **request.vulnerability,
            'scanner_types': available_scanners
        })
        
        return recommendations
    except Exception as e:
        logger.error(f"Error getting recommendations: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.post("/preventive-measures")
async def get_preventive_measures(request: RecommendationRequest, api_key: str = Depends(get_api_key)):
    """Get preventive measures based on code context"""
    if not AI_COMPONENTS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="AI-powered preventive measures are not available"
        )
    
    try:
        if not request.code_context:
            raise HTTPException(
                status_code=400,
                detail="Code context is required for preventive measures"
            )
        measures = recommender.get_preventive_measures(request.code_context)
        return {"measures": measures}
    except Exception as e:
        logger.error(f"Error getting preventive measures: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.post("/ai-analyze")
async def ai_analyze(request: Request, api_key: str = Depends(get_api_key)):
    """Perform AI-powered vulnerability analysis"""
    if not AI_COMPONENTS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="AI-powered analysis is not available"
        )
    
    try:
        data = await request.json()
        analysis_result = analyzer.analyze(data)
        return analysis_result
    except Exception as e:
        logger.error(f"Error in AI analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    return {"ai_results": results}

# Modify the scan endpoint to include recommendations
@app.post("/scan")
async def start_scan(config: ScanRequest, api_key: str = Depends(get_api_key)):
    # Generate unique scan ID
    scan_id = secrets.token_urlsafe(16)
    start_time = time.time()
    
    # Log the start of scanning
    await log_manager.broadcast(f"Starting scan for {config.target_url}")
    
    try:
        # Initialize crawler with configuration
        async with AdvancedCrawler(
            config.target_url, 
            max_pages=config.max_pages,
            delay=config.delay,
            user_agent=config.user_agent
        ) as crawler:
            # Perform crawling
            pages = await crawler.crawl()
            
            # Get registered scanners
            scanner_registry = ScannerRegistry()
            scanners = scanner_registry.get_all_scanners()
            await log_manager.broadcast(f"Available scanners: {', '.join([scanner.name for scanner in scanners])}")
            
            # Validate scan configuration
            crawler = AdvancedCrawler(config.target_url, max_pages=config.max_pages)
            await crawler.crawl()
            
            # Perform scanning
            # Map scan types to specific scanners
            scan_type_map = {
                'full': ['xss_scanner', 'sqli_scanner'],
                'xss': 'xss_scanner',
                'sqli': 'sqli_scanner'
            }
            
            # Determine scan type
            scanner_registry = ScannerRegistry()
            from importlib import import_module
            sqli_module = import_module('src.core.scanners.sqli')
            SQLiScanner = getattr(sqli_module, 'SQLiScanner')
            print(f"SQLiScanner details:")
            print(f"  Name: {SQLiScanner.name}")
            print(f"  Module: {SQLiScanner.__module__}")
            print(f"  Bases: {SQLiScanner.__bases__}")
            print(f"  Attributes: {dir(SQLiScanner)}")
            try:
                ScannerRegistry.register_scanner(SQLiScanner)
            except Exception as e:
                print(f"Failed to register SQLiScanner: {e}")
            # Direct debug for SQLiScanner
            from importlib import import_module
            import inspect
            try:
                sqli_module = import_module('src.core.scanners.sqli')
                print("\nDEBUG: Successfully imported SQLiScanner module")
                SQLiScanner = getattr(sqli_module, 'SQLiScanner')
                print(f"DEBUG: Found SQLiScanner class: {SQLiScanner}")
                print(f"DEBUG: SQLiScanner bases: {SQLiScanner.__bases__}")
                print(f"DEBUG: Is SQLiScanner a direct subclass of BaseScannerPlugin? {BaseScannerPlugin in SQLiScanner.__bases__}")
                print(f"DEBUG: SQLiScanner.__module__: {SQLiScanner.__module__}")
                print(f"DEBUG: Attempting direct registration...")
                ScannerRegistry.register_scanner(SQLiScanner)
                print(f"DEBUG: Registered scanners after direct registration: {ScannerRegistry.list_scanners()}")
            except Exception as e:
                print(f"\nERROR with SQLiScanner: {e}")

            # Initialize scanner registry
            ScannerRegistry.discover_scanners()

            # Directly import and register SQLiScanner
            from src.core.scanners.sqli import SQLiScanner
            print(f"Direct SQLiScanner import: {SQLiScanner}")
            print(f"SQLiScanner bases: {SQLiScanner.__bases__}")
            ScannerRegistry.register_scanner(SQLiScanner)
            print(f"Registered scanners after manual registration: {ScannerRegistry.list_scanners()}")

            # Default to xss_scanner if no scan type is specified
            if not config.scan_type or config.scan_type.lower() not in scan_type_map:
                scan_types = ['xss_scanner']
            else:
                # Resolve scan type
                type_key = config.scan_type.lower()
                scan_types = scan_type_map[type_key] if isinstance(scan_type_map[type_key], list) else [scan_type_map[type_key]]
            
            # Perform scanning
            scanner = Scanner(crawler.pages)
            vulnerabilities = []
            for scan_type in scan_types:
                type_vulnerabilities = await scanner.scan(scan_type)
                vulnerabilities.extend(type_vulnerabilities)
            
            # Generate scan statistics
            stats = {
                'total_pages': len(pages),
                'total_vulnerabilities': len(vulnerabilities),
                'scan_duration': time.time() - start_time,
                'available_scanners': available_scanners
            }
            
            # Store scan results
            scan_results[scan_id] = {
                'status': 'completed',
                'stats': stats,
                'vulnerabilities': vulnerabilities,
                'timestamp': datetime.now()
            }
            
            # Broadcast scan completion
            await log_manager.broadcast(f"Scan completed for {config.target_url}")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'stats': stats
            }
    
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        await log_manager.broadcast(f"Scan error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
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