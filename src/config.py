class Config:
    # Настройки краулера
    CRAWLER_DELAY = 1.0  # seconds
    MAX_PAGES = 100
    
    # Настройки Telegram
    TELEGRAM_TOKEN = "your_bot_token"
    TELEGRAM_CHAT_ID = "your_chat_id"
    
    # Пути к моделям ML
    FP_FILTER_MODEL = "models/fp_filter.pkl"