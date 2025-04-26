import logging
from core.scanners import http_client
from core.scanners.crawler import Crawler

logger = logging.getLogger("secscan")

def run_scan(target: str, scan_type: str):
    try:
        client = http_client.SecureHTTPClient()
        crawler = Crawler(client)
        
        results = {}
        
        if scan_type in ["full", "ports"]:
            results["ports"] = scan_ports(target)
        
        if scan_type in ["full", "dirs"]:
            results["directories"] = crawler.scan_directories(target)
        
        logger.info(f"Scan completed for {target}")
        return results
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise

def scan_ports(target: str):

    return {"open_ports": [80, 443]}