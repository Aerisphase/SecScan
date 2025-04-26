import requests
import ssl
from urllib3.util.ssl_ import create_urllib3_context

class SecureHTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.ssl_context = self._create_ssl_context()
        
    def _create_ssl_context(self):
        ctx = create_urllib3_context()
        ctx.load_verify_locations("ssl/server.crt")
        return ctx
        
    def get(self, url, timeout=5):
        return self.session.get(
            url,
            verify=True,
            ssl_context=self.ssl_context,
            timeout=timeout
        )