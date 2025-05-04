import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs
import requests
from ..http_client import HttpClient
from ..enhanced_http_client import EnhancedHttpClient

logger = logging.getLogger(__name__)

class BaseScanner:
    """Base scanner class that all scanners should inherit from"""
    
    def __init__(self, client=None):
        """Initialize the scanner with an HTTP client"""
        self.client = client if client else HttpClient()
        
        # Ensure the client has a headers attribute
        if not hasattr(self.client, 'headers'):
            self.client.headers = {}
            if hasattr(self.client, 'session') and hasattr(self.client.session, 'headers'):
                self.client.headers = self.client.session.headers.copy()
    
    def get_headers(self) -> Dict[str, str]:
        """Safely get headers from the client"""
        if hasattr(self.client, 'headers'):
            return self.client.headers
        elif hasattr(self.client, 'session') and hasattr(self.client.session, 'headers'):
            return self.client.session.headers
        return {}
    
    def set_headers(self, headers: Dict[str, str]) -> None:
        """Safely set headers on the client"""
        if hasattr(self.client, 'session') and hasattr(self.client.session, 'headers'):
            self.client.session.headers.update(headers)
        
        # Always update the client.headers attribute
        if not hasattr(self.client, 'headers'):
            self.client.headers = {}
        self.client.headers.update(headers)
