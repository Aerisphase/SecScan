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
from src.core.scanners.ssrf import SSRFScanner
from src.core.scanners.csrf import CSRFScanner
from src.core.scanners.ssti import SSTIScanner
from src.core.scanners.command_injection import CommandInjectionScanner
from src.core.scanners.path_traversal import PathTraversalScanner
from src.core.scanners.xxe import XXEScanner
from src.core.crawler import AdvancedCrawler
from src.config import API_KEY, API_KEY_NAME
from src.core.scanner import Scanner
from src.core.reporter import Reporter
# Import AI components
try:
    from src.ai.recommender import VulnerabilityRecommender
    from src.ai.vulnerability_analyzer import VulnerabilityAnalyzer
    recommender = VulnerabilityRecommender()
    analyzer = VulnerabilityAnalyzer()
    ai_available = True
except ImportError as e:
    print(f"AI components not available: {e}")
    recommender = None
    analyzer = None
    ai_available = False

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
    scanners: List[str] = ["xss", "sqli", "ssrf", "csrf", "ssti", "cmdInjection", "pathTraversal", "xxe"]
    delay: float = 1.0
    max_pages: int = 20
    user_agent: Optional[str] = None
    js_enabled: bool = False
    browser_timeout: int = 30000
    wait_for_idle: bool = True
    waf_evasion: bool = False
    rotate_user_agent: bool = False
    randomize_headers: bool = False
    maintain_session: bool = True
    handle_csrf: bool = True

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
async def get_preventive_measures(request: Request, api_key: str = Depends(get_api_key)):
    data = await request.json()
    code_context = data.get("code_context", "")
    
    # TODO: Implement AI-powered preventive measures
    measures = [
        "Implement input validation for all user inputs",
        "Use parameterized queries for database operations",
        "Apply Content Security Policy headers",
        "Sanitize user input before rendering in HTML",
        "Keep all dependencies up to date"
    ]
    
    return {"measures": measures}

# Endpoint for AI analysis of vulnerabilities
@app.post("/ai-analyze")
async def analyze_vulnerabilities(request: Request, api_key: str = Depends(get_api_key)):
    if not ai_available or not analyzer:
        return {"error": "AI components not available"}
        
    data = await request.json()
    vulnerabilities = data.get("vulnerabilities", [])
    
    # Log received vulnerabilities
    logging.info(f"[AI ANALYZE] Received {len(vulnerabilities)} vulnerabilities for analysis")
    
    try:
        # Use the analyze_vulnerabilities method we added
        results = analyzer.analyze_vulnerabilities(vulnerabilities)
        logging.info(f"[AI ANALYZE] Analysis completed successfully")
        return {"ai_results": results}
    except Exception as e:
        logging.error(f"[AI ANALYZE] Error during analysis: {str(e)}")
        return {"error": f"Analysis failed: {str(e)}"}

@app.post("/ai-analyze")
async def ai_analyze(request: Request, api_key: str = Depends(get_api_key)):
    if not ai_available or not analyzer:
        return {"error": "AI components not available"}
        
    data = await request.json()
    vulnerabilities = data.get("vulnerabilities", [])
    logging.info(f"[AI ANALYZE] Received {len(vulnerabilities)} vulnerabilities for analysis")
    
    try:
        # Use the analyze_vulnerabilities method we added
        results = analyzer.analyze_vulnerabilities(vulnerabilities)
        logging.info(f"[AI ANALYZE] Analysis completed successfully")
        return {"ai_results": results}
    except Exception as e:
        logging.error(f"[AI ANALYZE] Error during analysis: {str(e)}")
        return {"error": f"Analysis failed: {str(e)}"}

# Modify the scan endpoint to include recommendations
@app.post("/scan")
async def start_scan(config: ScanRequest, api_key: str = Depends(get_api_key)):
    try:
        start_time = time.time()
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Use the configured max_pages
        max_pages = config.max_pages
        
        # Initialize components
        crawler = AdvancedCrawler(
            base_url=config.target_url,
            max_pages=max_pages,
            delay=config.delay,
            user_agent=config.user_agent,
            log_manager=log_manager  # Pass log_manager for real-time updates
        )
        
        scanner = Scanner()
        reporter = Reporter()
        
        # Create HTTP client and initialize scanners before crawling to reduce delay
        from src.core.http_client import HttpClient
        from src.core.enhanced_http_client import EnhancedHttpClient
        
        # Send update about initializing the HTTP client
        await log_manager.broadcast(f"Initializing HTTP client...")
        
        # Use enhanced HTTP client for better vulnerability detection
        http_client = EnhancedHttpClient(
            verify_ssl=False,
            timeout=10,
            max_retries=3,
            rate_limit_min=config.delay,
            rate_limit_max=config.delay * 2,
            proxy=None,
            auth=None,
            rotate_user_agent=True,  # Enable our new WAF bypass features
            rotate_request_pattern=True,
            waf_evasion=True,
            handle_csrf=True,
            maintain_session=True
        )
        
        if config.user_agent:
            http_client.session.headers['User-Agent'] = config.user_agent
        
        # Send update about initializing scanners
        await log_manager.broadcast(f"Initializing scanners: {', '.join(config.scanners)}")
        
        # Initialize all scanners in parallel using asyncio tasks
        all_scanners = {}
        scanner_init_tasks = []
        
        # Create initialization tasks for selected scanners
        for scanner_name in config.scanners:
            if scanner_name == 'xss':
                all_scanners['xss'] = XSSScanner(http_client)
            elif scanner_name == 'sqli':
                all_scanners['sqli'] = SQLiScanner(http_client)
            elif scanner_name == 'ssrf':
                all_scanners['ssrf'] = SSRFScanner(http_client)
            elif scanner_name == 'csrf':
                all_scanners['csrf'] = CSRFScanner(http_client)
            elif scanner_name == 'ssti':
                all_scanners['ssti'] = SSTIScanner(http_client)
            elif scanner_name == 'cmdInjection':
                all_scanners['cmdInjection'] = CommandInjectionScanner(http_client)
            elif scanner_name == 'pathTraversal':
                all_scanners['pathTraversal'] = PathTraversalScanner(http_client)
            elif scanner_name == 'xxe':
                all_scanners['xxe'] = XXEScanner(http_client)
        
        await log_manager.broadcast(f"Scanners initialized successfully")
        
        # Start crawling
        await log_manager.broadcast(f"Starting crawl of {config.target_url}")
        pages = await crawler.crawl()
        await log_manager.broadcast(f"Crawling completed. Found {len(pages)} pages")
        
        # Send update that scanning is about to begin
        await log_manager.broadcast(f"Preparing to scan with: {', '.join(all_scanners.keys())}")
        await asyncio.sleep(0.1)  # Small delay to ensure message is sent
        
        # Scan each page
        vulnerabilities = []
        
        # Send immediate update that scanning is starting
        await log_manager.broadcast(f"Starting scan of {len(pages)} pages...")
        await asyncio.sleep(0.1)  # Ensure message is sent
        
        # Create a custom scanner class that broadcasts updates in real-time
        class BroadcastingScanner(Scanner):
            async def scan_page(self, page_data, selected_scanners=None):
                try:
                    page_vulnerabilities = []
                    url = page_data.get('url', '')
                    forms = page_data.get('forms', [])
                    
                    # Use the pre-initialized scanners and HTTP client
                    # This avoids the delay caused by initializing them for each page
                    
                    # Run each selected scanner on the page
                    for scanner_name, scanner in all_scanners.items():
                        try:
                            # Broadcast the start of each scanner and ensure it's sent immediately
                            await log_manager.broadcast(f"Running {scanner_name.upper()} scanner on {url}")
                            await asyncio.sleep(0.05)  # Small delay to ensure message is sent
                            
                            # Run the scanner with a progress update wrapper
                            async def run_scanner_with_progress():
                                # Convert synchronous scan to asynchronous with progress updates
                                loop = asyncio.get_event_loop()
                                progress_task = asyncio.create_task(self._send_progress_updates(scanner_name, url, log_manager))
                                vulns = await loop.run_in_executor(None, lambda: scanner.scan(url, forms))
                                progress_task.cancel()  # Stop progress updates when scan completes
                                return vulns
                                
                            vulns = await run_scanner_with_progress()
                            
                            # Send immediate result
                            if vulns:
                                page_vulnerabilities.extend(vulns)
                                await log_manager.broadcast(f"Found {len(vulns)} {scanner_name.upper()} vulnerabilities on {url}")
                            else:
                                await log_manager.broadcast(f"No {scanner_name.upper()} vulnerabilities found on {url}")
                            await asyncio.sleep(0.05)  # Ensure message is sent
                            
                        except Exception as e:
                            self.logger.error(f"{scanner_name} scanner failed on {url}: {str(e)}")
                            await log_manager.broadcast(f"Error in {scanner_name.upper()} scanner: {str(e)}")
                            await asyncio.sleep(0.05)  # Ensure message is sent
                    
                    return page_vulnerabilities
                    
                except Exception as e:
                    self.logger.error(f"Error scanning page {url}: {str(e)}")
                    await log_manager.broadcast(f"Error scanning page {url}: {str(e)}")
                    return []
            
            async def _send_progress_updates(self, scanner_name, url, log_manager):
                """Send periodic progress updates during long-running scans"""
                dots = 0
                try:
                    while True:
                        dots = (dots % 3) + 1
                        await log_manager.broadcast(f"[PROGRESS] {scanner_name.upper()} scanner running on {url}{'.' * dots}")
                        await asyncio.sleep(2.0)  # Update every 2 seconds
                except asyncio.CancelledError:
                    # Task was cancelled, which is expected when scan completes
                    pass
        
        # Process pages in batches to improve UI responsiveness
        batch_size = 5  # Process 5 pages at a time for better progress visibility
        for i in range(0, len(pages), batch_size):
            batch = pages[i:i+batch_size]
            batch_start = i + 1
            batch_end = min(i + len(batch), len(pages))
            
            await log_manager.broadcast(f"Scanning pages {batch_start}-{batch_end}/{len(pages)}...")
            await asyncio.sleep(0.1)  # Ensure message is sent
            
            # Process each page in the batch
            for j, page in enumerate(batch):
                page_index = i + j + 1
                await log_manager.broadcast(f"Scanning page {page_index}/{len(pages)}: {page['url']}")
                await asyncio.sleep(0.1)  # Ensure message is sent
                
                # Use our custom scanner
                broadcasting_scanner = BroadcastingScanner()
                page_vulns = await broadcasting_scanner.scan_page(page, config.scanners)
            
            if page_vulns:
                # Add recommendations to each vulnerability
                for vuln in page_vulns:
                    recommendations = recommender.get_recommendations(vuln)
                    vuln['recommendations'] = recommendations['recommendations']
                    vuln['prevention_score'] = recommendations['prevention_score']
                    vuln['confidence'] = recommendations['confidence']
                vulnerabilities.extend(page_vulns)
                await log_manager.broadcast(f"Found {len(page_vulns)} total vulnerabilities on {page['url']}")
            else:
                await log_manager.broadcast(f"No vulnerabilities found on {page['url']}")

        
        # Generate report
        report = reporter.generate_report(
            target_url=config.target_url,
            pages_crawled=len(pages),
            vulnerabilities_found=vulnerabilities,
            scan_type="custom",  # Using 'custom' since we're using selected scanners now
            elapsed_time=time.time() - start_time
        )
        
        # Store results
        scan_results[scan_id] = report
        await log_manager.broadcast("Scan completed successfully")
        
        return report
        
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