import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API configuration
API_KEY_NAME = "X-API-Key"
API_KEY = os.getenv("SECSCAN_API_KEY")

# Telegram integration
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Server configuration
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
SSL_CERT_PATH = os.getenv("SSL_CERT_PATH")
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH")

class Config:
    # Crawler settings
    CRAWLER_DELAY = 1.0  # seconds
    MAX_PAGES = 100
    
    # Telegram settings
    TELEGRAM_TOKEN = TELEGRAM_TOKEN
    TELEGRAM_CHAT_ID = TELEGRAM_CHAT_ID
    
    # ML model paths
    FP_FILTER_MODEL = "models/fp_filter.pkl"