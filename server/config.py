import os

class ServerConfig:
    HOST = os.getenv("SECSCAN_HOST", "0.0.0.0")
    PORT = int(os.getenv("SECSCAN_PORT", 8443))
    MAX_WORKERS = int(os.getenv("SECSCAN_MAX_WORKERS", 10))
    SSL_CERT = "ssl/server.crt"
    SSL_KEY = "ssl/server.key"

class Config:
    # Настройки краулера
    CRAWLER_DELAY = 1.0  # seconds
    MAX_PAGES = 100
    
    # Настройки Telegram
    TELEGRAM_TOKEN = "your_bot_token"
    TELEGRAM_CHAT_ID = "your_chat_id"
    
    # Пути к моделям ML
    FP_FILTER_MODEL = "models/fp_filter.pkl"