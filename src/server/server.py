import os
import sys
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
from src.ai.recommender import VulnerabilityRecommender
from src.ai.vulnerability_analyzer import VulnerabilityAnalyzer

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Server')

# Define security header analysis function
def analyze_security_headers(headers):
    """Analyze security headers and return recommendations"""
    recommendations = []
    
    # Check for important security headers
    if 'X-XSS-Protection' not in headers:
        recommendations.append({
            'header': 'X-XSS-Protection',
            'value': '1; mode=block',
            'description': 'Enables XSS filtering in browsers to block XSS attacks'
        })
    
    if 'X-Content-Type-Options' not in headers:
        recommendations.append({
            'header': 'X-Content-Type-Options',
            'value': 'nosniff',
            'description': 'Prevents browsers from MIME-sniffing a response from declared content-type'
        })
    
    if 'X-Frame-Options' not in headers:
        recommendations.append({
            'header': 'X-Frame-Options',
            'value': 'DENY',
            'description': 'Prevents clickjacking attacks by disallowing framing of your site'
        })
    
    if 'Content-Security-Policy' not in headers:
        recommendations.append({
            'header': 'Content-Security-Policy',
            'value': "default-src 'self'",
            'description': 'Helps prevent XSS and data injection attacks by specifying valid content sources'
        })
    
    if 'Strict-Transport-Security' not in headers:
        recommendations.append({
            'header': 'Strict-Transport-Security',
            'value': 'max-age=31536000; includeSubDomains',
            'description': 'Enforces HTTPS connections for enhanced security'
        })
    
    return recommendations

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
    waf_bypass: bool = False

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
        self.heartbeat_task = None

    async def connect(self, websocket: WebSocket):
        try:
            async with self.connection_lock:
                # Check if connection already exists
                if websocket in self.active_connections:
                    self.logger.warning("WebSocket connection already exists")
                    return
                    
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
                    except WebSocketDisconnect:
                        self.logger.info(f"WebSocket disconnected during broadcast")
                        disconnected.append(connection)
                    except Exception as e:
                        self.logger.error(f"Error broadcasting message: {str(e)}")
                        disconnected.append(connection)
            
            # Remove disconnected connections
            for connection in disconnected:
                try:
                    await self.disconnect(connection)
                except Exception as e:
                    self.logger.error(f"Error disconnecting connection: {str(e)}")

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
recommender = VulnerabilityRecommender()
analyzer = VulnerabilityAnalyzer()

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
    try:
        recommendations = recommender.get_recommendations(request.vulnerability)
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
    data = await request.json()
    vulnerabilities = data.get("vulnerabilities", [])
    print("[AI ANALYZE] Received vulnerabilities:", vulnerabilities)
    results = []
    for vuln in vulnerabilities:
        result = analyzer.analyze_vulnerability(
            vuln.get("type", ""),
            vuln.get("evidence", vuln.get("details", "")),
            vuln.get("payload", "")
        )
        results.append(result)
    print("[AI ANALYZE] AI results:", results)
    return {"ai_results": results}

# Modify the scan endpoint to include recommendations
@app.post("/scan")
async def start_scan(config: ScanRequest, api_key: str = Depends(get_api_key)):
    # Create a heartbeat task to keep the WebSocket connection alive
    heartbeat_task = None
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_results = {}
    
    try:
        # Send initial scan message to all clients
        await log_manager.broadcast(f"Starting scan of {config.target_url}")
        
        # Set max_pages based on scan type
        max_pages = 100 if config.scan_type == "full" else config.max_pages
        
        # Initialize components
        crawler = AdvancedCrawler(
            base_url=config.target_url,
            max_pages=max_pages,
            delay=config.delay,
            user_agent=config.user_agent
        )
        
        # Initialize scanner with WAF bypass if enabled
        scanner_config = {
            'scan_type': config.scan_type,
            'waf_bypass': config.waf_bypass
        }
        scanner = Scanner(scanner_config)
        reporter = Reporter()
        
        # Create a background task for sending heartbeats during scanning
        async def send_heartbeats():
            try:
                heartbeat_count = 0
                while True:
                    heartbeat_count += 1
                    # Vary the message to avoid WebSocket optimization dropping "duplicate" messages
                    if heartbeat_count % 5 == 0:
                        await log_manager.broadcast(f"Scan in progress... (heartbeat {heartbeat_count})")
                    else:
                        await log_manager.broadcast("Scan in progress...")
                    await asyncio.sleep(2)  # More frequent heartbeats (2 seconds)
            except asyncio.CancelledError:
                # Task was cancelled, clean exit
                logger.info("Heartbeat task cancelled")
            except Exception as e:
                logger.error(f"Heartbeat error: {str(e)}")
        
        # Start the heartbeat task
        heartbeat_task = asyncio.create_task(send_heartbeats())
        
        # Initialize scanner with config
        scanner = Scanner(
            target_url=config.target_url,
            scan_type=config.scan_type,
            max_pages=config.max_pages,
            delay=config.delay,
            user_agent=config.user_agent,
            cookies=config.cookies,
            headers=config.headers,
            waf_bypass=config.waf_bypass,
            custom_payloads=config.custom_payloads,
            exclude_patterns=config.exclude_patterns,
            include_patterns=config.include_patterns,
            timeout=config.timeout,
            log_manager=log_manager
        )
        
        # Run the scan with periodic status updates
        try:
            # Send a message before starting the scan
            await log_manager.broadcast("Initializing scanner...")
            
            # Run the scan in a separate thread to avoid blocking the event loop
            scan_results = await asyncio.to_thread(scanner.scan, config.target_url)
            
            # Send a message after scan completes
            await log_manager.broadcast("Scan execution completed, generating report...")
            
            if scan_results:
                # Generate report
                reporter = Reporter(scan_results)
                final_report = reporter.generate_report()
                
                # Store results
                scan_results[scan_id] = final_report
                
                # Calculate scan time
                end_time = time.time()
                scan_duration = end_time - start_time
                
                # Log completion
                logger.info(f"Scan completed: {scan_id} in {scan_duration:.2f} seconds")
                await log_manager.broadcast(f"Scan completed in {scan_duration:.2f}s")
                
                # Keep the connection alive for a moment after scan completion
                await asyncio.sleep(1)
                
                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "duration": scan_duration,
                    "result_url": f"/scan/{scan_id}"
                }
            else:
                logger.error(f"Scan failed: {scan_id}")
                await log_manager.broadcast("Scan failed - no results returned")
                raise HTTPException(
                    status_code=500,
                    detail="Scan failed to complete"
                )
        except Exception as e:
            logger.error(f"Error during scan execution: {str(e)}")
            await log_manager.broadcast(f"Scan error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=str(e)
            )
    except Exception as e:
        logger.error(f"Scan setup error: {str(e)}")
        await log_manager.broadcast(f"Scan setup error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    finally:
        # Always cancel the heartbeat task if it exists
        if heartbeat_task:
            try:
                logger.info("Cleaning up heartbeat task")
                heartbeat_task.cancel()
                await asyncio.sleep(0.5)  # Give it more time to clean up
            except Exception as e:
                logger.error(f"Error cancelling heartbeat task: {str(e)}")
        
        # Send a final message to confirm everything is done
        try:
            await log_manager.broadcast(f"Scan process for {scan_id} completed")
        except Exception as e:
            logger.error(f"Error sending final message: {str(e)}")

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
        # Accept connection without protocol requirements
        await websocket.accept()
        logger.info("WebSocket connection accepted")
            
        await log_manager.connect(websocket)
        logger.info("WebSocket connection established successfully")
        
        # Send initial message to confirm connection
        try:
            await websocket.send_text(json.dumps({'type': 'connected', 'message': 'Connection established'}))
        except Exception as e:
            logger.error(f"Error sending initial message: {str(e)}")
        
        # Set up ping/pong for connection keepalive
        ping_interval = 5  # seconds - more frequent pings
        last_ping_time = time.time()
        last_activity_time = time.time()
        
        # Create a background task for sending pings
        async def send_pings():
            nonlocal last_ping_time
            try:
                while True:
                    await asyncio.sleep(ping_interval)
                    try:
                        # Only send ping if we haven't sent one recently
                        current_time = time.time()
                        if current_time - last_ping_time >= ping_interval:
                            await websocket.send_text(json.dumps({'type': 'ping'}))
                            last_ping_time = current_time
                            logger.debug("Sent ping to client")
                    except Exception as e:
                        logger.error(f"Error in ping task: {str(e)}")
                        break
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Ping task error: {str(e)}")
        
        # Start the ping task
        ping_task = asyncio.create_task(send_pings())
        
        try:
            # Main message handling loop
            while True:
                try:
                    # Wait for message with a reasonable timeout
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                    last_activity_time = time.time()
                    
                    # Handle messages
                    try:
                        message = json.loads(data)
                        if message.get('type') == 'ping':
                            # Respond to ping immediately
                            await websocket.send_text(json.dumps({'type': 'pong'}))
                            logger.debug("Received ping, sent pong")
                        elif message.get('type') == 'pong':
                            # Pong received, connection is good
                            logger.debug("Received pong from client")
                        else:
                            # Process other messages
                            await log_manager.broadcast(json.dumps(message))
                    except json.JSONDecodeError:
                        logger.warning(f"Received invalid JSON message: {data}")
                        
                except asyncio.TimeoutError:
                    # Just continue the loop - the ping task will handle keepalive
                    continue
                    
        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {str(e)}")
            await websocket.close(code=1011, reason="Internal server error")
        finally:
            # Always cancel the ping task
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass
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