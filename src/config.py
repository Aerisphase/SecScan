import os
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

# Конфигурация API
API_KEY_NAME = "X-API-Key"
API_KEY = os.getenv("SECSCAN_API_KEY")

# Интеграция с Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Конфигурация сервера
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
SSL_CERT_PATH = os.getenv("SSL_CERT_PATH")
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH")

class Config:
    # Настройки краулера
    CRAWLER_DELAY = 1.0  # секунды
    MAX_PAGES = 100
    
    # Настройки Telegram
    TELEGRAM_TOKEN = TELEGRAM_TOKEN
    TELEGRAM_CHAT_ID = TELEGRAM_CHAT_ID
    
    # Пути к ML моделям
    FP_FILTER_MODEL = "models/fp_filter.pkl"