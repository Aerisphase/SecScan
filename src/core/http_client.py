import requests
import logging

class HttpClient:
    def __init__(self, verify_ssl=True, timeout=10):
        self.verify = verify_ssl
        self.timeout = timeout

    def get(self, url, **kwargs):
        try:
            response = requests.get(
                url,
                verify=self.verify,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except requests.exceptions.Timeout:
            logging.error(f"Timeout occurred for {url}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Connection error for {url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {url}: {e}")
        return None